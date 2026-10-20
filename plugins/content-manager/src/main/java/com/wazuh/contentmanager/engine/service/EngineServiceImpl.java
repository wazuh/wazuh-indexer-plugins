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
package com.wazuh.contentmanager.engine.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.core.action.ActionListener;
import org.opensearch.threadpool.ThreadPool;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import com.wazuh.contentmanager.engine.client.EngineSocketClient;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

public class EngineServiceImpl implements EngineService {
    public static final String LOGTEST = "logtest";
    static final String VALIDATE = "/content/validate/resource";
    static final String PROMOTE = "/content/validate/policy";
    static final String IOC_UPDATE = "/content/ioc/update";
    static final String IOC_STATE = "/content/ioc/state";

    private final EngineSocketClient socket;
    private final ObjectMapper mapper;
    private final ThreadPool threadPool;

    /** Guards {@link #lastPromote}. */
    private final Object promoteLock = new Object();

    /**
     * Completes when the last promote queued by {@link #promoteAsync} has finished, successfully or
     * not. Each new promote is chained after it.
     */
    private CompletableFuture<Void> lastPromote = CompletableFuture.completedFuture(null);

    /**
     * Production constructor.
     *
     * @param threadPool used by {@link #promoteAsync} to offload blocking socket I/O.
     */
    public EngineServiceImpl(ThreadPool threadPool) {
        this(new EngineSocketClient(), threadPool);
    }

    /**
     * Test constructor.
     *
     * @param socket instance of {@link EngineSocketClient}
     * @param threadPool used by {@link #promoteAsync} to offload blocking socket I/O.
     */
    public EngineServiceImpl(EngineSocketClient socket, ThreadPool threadPool) {
        this.socket = socket;
        this.mapper = new ObjectMapper();
        this.threadPool = threadPool;
    }

    @Override
    public RestResponse logtest(JsonNode log) {
        return this.socket.sendRequest(LOGTEST, POST.name(), log);
    }

    @Override
    public RestResponse validate(JsonNode resource) {
        return this.socket.sendRequest(VALIDATE, POST.name(), resource);
    }

    @Override
    public RestResponse promote(JsonNode policy) {
        return this.socket.sendRequest(PROMOTE, POST.name(), policy);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The promotes of this node are sent to the Engine one at a time, in the order they were
     * requested. The Engine replaces a space's session in several steps that are not serialized, and
     * fails two promotes of the same space that overlap ("environment already exists", "Namespace
     * does not exist"). Each promote is queued behind the previous one without holding a thread while
     * it waits, and only the Engine call is queued: the listener is notified outside the queue, so
     * its own work never delays, or stops, the next promote.
     */
    @Override
    public void promoteAsync(JsonNode policy, ActionListener<RestResponse> listener) {
        CompletableFuture<RestResponse> call;
        synchronized (this.promoteLock) {
            call =
                    this.lastPromote.thenApplyAsync(
                            ignored -> this.promote(policy), this.threadPool.generic());
            this.lastPromote = call.handle((response, e) -> null);
        }
        call.whenComplete(
                (response, e) -> {
                    if (e == null) {
                        listener.onResponse(response);
                    } else {
                        Throwable cause = e instanceof CompletionException ? e.getCause() : e;
                        listener.onFailure(
                                cause instanceof Exception exception ? exception : new RuntimeException(cause));
                    }
                });
    }

    @Override
    public RestResponse validateResource(String type, JsonNode resource) {
        ObjectNode payload = this.mapper.createObjectNode();
        payload.put(Constants.KEY_TYPE, type);
        payload.set(Constants.KEY_RESOURCE, resource);
        return this.validate(payload);
    }

    @Override
    public RestResponse getIocState() {
        return this.socket.sendRequest(IOC_STATE, GET.name(), this.mapper.createObjectNode());
    }

    @Override
    public RestResponse updateIoc(String filePath, String hash) {
        ObjectNode payload = this.mapper.createObjectNode();
        payload.put("path", filePath);
        payload.put("hash", hash);
        return this.socket.sendRequest(IOC_UPDATE, POST.name(), payload);
    }
}
