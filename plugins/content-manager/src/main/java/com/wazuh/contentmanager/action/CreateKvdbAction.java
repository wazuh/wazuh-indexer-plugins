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
package com.wazuh.contentmanager.action;

import org.opensearch.action.ActionType;

/** Action type for CreateKvdb transport action. */
public class CreateKvdbAction extends ActionType<ContentResponse> {
    public static final String NAME = "indices:data/write/content_manager/kvdb/create";
    public static final CreateKvdbAction INSTANCE = new CreateKvdbAction();

    public CreateKvdbAction() {
        super(NAME, ContentResponse::new);
    }
}
