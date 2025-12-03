package com.wazuh.contentmanager.cti.catalog.service;

/**
 * Service interface for managing CTI snapshots.
 * Defines the contract for initializing consumers from remote snapshots.
 */
public interface UpdateService {

    /**
     * Performs a content update within the specified offset range.
     *
     * @param fromOffset The starting offset (exclusive) to fetch changes from.
     * @param toOffset   The target offset (inclusive) to reach.
     */
    void update(long fromOffset, long toOffset);
}
