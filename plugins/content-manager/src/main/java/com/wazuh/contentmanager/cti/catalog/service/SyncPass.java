/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.cti.catalog.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.console.model.Feature;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.CtiConsoleUnavailableException;
import com.wazuh.contentmanager.cti.console.service.PlansServiceImpl;
import com.wazuh.contentmanager.cti.console.service.TokenRejectedException;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * One synchronization pass: the subscription plan, looked up once when the pass starts, and what
 * the pass's swap did to each consumer.
 *
 * <p>Every consumer, and the {@link ShadowSwapService} that moves them to a new data source, reads
 * the plan from here. A pass therefore never splits its consumers across two plans, and the CTI
 * Console is asked once per pass instead of once per consumer.
 */
public final class SyncPass {
    private static final Logger log = LogManager.getLogger(SyncPass.class);

    /** What the swap of a pass did to a consumer. */
    public enum SwapOutcome {
        /** The consumer stays on its data source and is synchronized as usual. */
        UNCHANGED,
        /** The consumer was moved to its new data source in this pass. */
        SWAPPED,
        /**
         * The data source of the consumer changes but the swap could not run. Its document still
         * describes its live content, which is kept until a swap succeeds.
         */
        PENDING,
        /**
         * The consumer is left untouched in this pass: a swap that was interrupted could not be redone,
         * or whether one is pending could not be determined. Its document may name the data source a
         * swap is moving it to rather than its live content, so neither is changed.
         */
        HELD
    }

    /** The plan of a registered instance, or {@code null} when there is no plan to apply. */
    private final Plan plan;

    /** Whether the CTI Console rejected the access token of a registered instance. */
    private final boolean tokenRejected;

    /** Why the plan of a registered instance could not be looked up, or {@code null}. */
    private final CtiConsoleUnavailableException planFailure;

    private final Map<String, SwapOutcome> swapOutcomes = new HashMap<>();
    private final Map<String, AbstractConsumerService.ContentSource> contentSources = new HashMap<>();

    private SyncPass(Plan plan, boolean tokenRejected, CtiConsoleUnavailableException planFailure) {
        this.plan = plan;
        this.tokenRejected = tokenRejected;
        this.planFailure = planFailure;
    }

    /**
     * Starts a pass, looking up the plan of a registered instance in the CTI Console.
     *
     * @return the pass. An unregistered instance, a rejected token and a plan the Console does not
     *     return all leave the pass without a plan; a lookup that fails leaves the plan unknown.
     */
    public static SyncPass resolve() {
        if (!PluginSettings.getInstance().isRegistered()) {
            return new SyncPass(null, false, null);
        }
        PlansServiceImpl plansService = null;
        try {
            plansService = new PlansServiceImpl();
            Plan plan =
                    plansService.getMyPlan(
                            new Token(PluginSettings.getInstance().getAccessToken(), "Bearer"));
            if (plan == null) {
                log.debug(Constants.D_LOG_NO_PLAN_RETURNED);
            }
            return new SyncPass(plan, false, null);
        } catch (TokenRejectedException e) {
            return new SyncPass(null, true, null);
        } catch (CtiConsoleUnavailableException e) {
            return new SyncPass(null, false, e);
        } catch (Exception e) {
            return new SyncPass(null, false, new CtiConsoleUnavailableException(e.getMessage(), e));
        } finally {
            if (plansService != null) {
                plansService.close();
            }
        }
    }

    /**
     * Starts a pass that applies the given plan, without asking the CTI Console.
     *
     * @param plan the plan, or {@code null} for an instance without one.
     * @return the pass.
     */
    public static SyncPass withPlan(Plan plan) {
        return new SyncPass(plan, false, null);
    }

    /**
     * Starts a pass whose plan could not be looked up, without asking the CTI Console.
     *
     * @param reason why the lookup failed.
     * @return the pass.
     */
    public static SyncPass withUnknownPlan(String reason) {
        return new SyncPass(null, false, new CtiConsoleUnavailableException(reason));
    }

    /**
     * Returns the data source the plan provides for a consumer.
     *
     * @param consumerType the consumer type to look up (e.g., {@code
     *     "cti:catalog:consumer:ruleset"}).
     * @return the feature's resource URL, or {@code null} if there is no plan to apply or it has no
     *     feature for the consumer.
     * @throws CtiConsoleUnavailableException if the plan of a registered instance could not be looked
     *     up, so whether it provides a resource is unknown.
     */
    public String planResource(String consumerType) throws CtiConsoleUnavailableException {
        if (this.planFailure != null) {
            throw this.planFailure;
        }
        if (this.tokenRejected) {
            log.debug(Constants.D_LOG_PLAN_TOKEN_REJECTED, consumerType);
            return null;
        }
        if (this.plan == null) {
            return null;
        }
        Feature feature = this.plan.getFeature(consumerType);
        if (feature == null) {
            log.debug(Constants.D_LOG_NO_FEATURE_FOR_CONSUMER, consumerType, this.plan.getName());
            return null;
        }
        log.debug(
                Constants.D_LOG_PLAN_PROVIDES_RESOURCE,
                this.plan.getName(),
                feature.getResource(),
                consumerType);
        return feature.getResource();
    }

    /**
     * Returns what the swap of this pass did to a consumer.
     *
     * @param consumerType the consumer type.
     * @return the outcome; {@link SwapOutcome#UNCHANGED} when none was recorded.
     */
    public SwapOutcome swapOutcome(String consumerType) {
        return this.swapOutcomes.getOrDefault(consumerType, SwapOutcome.UNCHANGED);
    }

    /**
     * Records what the swap of this pass did to a consumer.
     *
     * @param consumerType the consumer type.
     * @param outcome the outcome.
     */
    void recordSwapOutcome(String consumerType, SwapOutcome outcome) {
        this.swapOutcomes.put(consumerType, outcome);
    }

    /**
     * Returns the content source resolved for a consumer in this pass.
     *
     * @param consumerType the consumer type.
     * @return the source, or {@code null} if none was resolved yet.
     */
    AbstractConsumerService.ContentSource contentSource(String consumerType) {
        return this.contentSources.get(consumerType);
    }

    /**
     * Records the content source resolved for a consumer, so the rest of the pass uses the same one
     * and the plan-related messages are logged once.
     *
     * @param consumerType the consumer type.
     * @param source the source.
     */
    void recordContentSource(String consumerType, AbstractConsumerService.ContentSource source) {
        this.contentSources.put(consumerType, source);
    }
}
