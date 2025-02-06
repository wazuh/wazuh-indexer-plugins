/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.commandmanager.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.*;
import org.opensearch.search.SearchHit;

import java.io.IOException;
import java.util.Objects;

import reactor.util.annotation.NonNull;

/** Order model class. */
public class Order implements ToXContent {
	public static final String SOURCE = "source";
	public static final String USER = "user";
	public static final String DOCUMENT_ID = "document_id";
	private final String source;
	private final Target target;
	private final String user;
	private final Action action;
	private final String documentId;

	private static final Logger log = LogManager.getLogger(Order.class);

	/**
	 * Default constructor
	 *
	 * @param source String field representing the origin of the command order
	 * @param target Object containing the destination's type and id. It is handled by its own model
	 *     class
	 * @param user The requester of the command
	 * @param action An object containing the actual executable plus arguments and version. Handled by
	 *     its own model class
	 * @param documentId The document ID from the index that holds commands. Used by the agent to
	 *     report back the results of the action
	 */
	public Order(
			@NonNull String source,
			@NonNull Target target,
			@NonNull String user,
			@NonNull Action action,
			@NonNull String documentId) {
		this.source = source;
		this.target = target;
		this.user = user;
		this.action = action;
		this.documentId = documentId;
	}

	/**
	 * Parses a SearchHit into an order as expected by a Wazuh Agent
	 *
	 * @param hit The SearchHit result of a search
	 * @return An Order Object in accordance with the data model
	 */
	public static Order fromSearchHit(SearchHit hit) {
		try {
			XContentParser parser =
					XContentHelper.createParser(
							NamedXContentRegistry.EMPTY,
							DeprecationHandler.IGNORE_DEPRECATIONS,
							hit.getSourceRef(),
							XContentType.JSON);
			Command command = null;
			// Iterate over the JsonXContentParser's JsonToken until we hit null,
			// which corresponds to end of data
			while (parser.nextToken() != null) {
				// Look for FIELD_NAME JsonToken s
				if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
					String fieldName = parser.currentName();
					if (fieldName.equals(Command.COMMAND)) {
						// Parse Command
						command = Command.parse(parser);
					} else {
						parser.skipChildren();
					}
				}
			}
			// Create a new Order object with the Command's fields
			return new Order(
					Objects.requireNonNull(command).getSource(),
					Objects.requireNonNull(command).getTarget(),
					Objects.requireNonNull(command).getUser(),
					Objects.requireNonNull(command).getAction(),
					Objects.requireNonNull(hit).getId());
		} catch (IOException e) {
			log.error("Order could not be parsed: {}", e.getMessage());
		} catch (NullPointerException e) {
			log.error(
					"Could not create Order object. One or more of the constructor's arguments was null: {}",
					e.getMessage());
		}
		return null;
	}

	/**
	 * Used to serialize the Order's contents.
	 *
	 * @param builder The builder object we will add our Json to
	 * @param params Not used. Required by the interface.
	 * @return XContentBuilder with a Json object including this Order's fields
	 * @throws IOException Rethrown from IOException's XContentBuilder methods
	 */
	@Override
	public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
		builder.startObject();
		builder.field(SOURCE, this.source);
		builder.field(USER, this.user);
		this.target.toXContent(builder, ToXContent.EMPTY_PARAMS);
		this.action.toXContent(builder, ToXContent.EMPTY_PARAMS);
		builder.field(DOCUMENT_ID, this.documentId);

		return builder.endObject();
	}

	@Override
	public String toString() {
		return "Order{"
				+ "action="
				+ action
				+ ", source='"
				+ source
				+ '\''
				+ ", target="
				+ target
				+ ", user='"
				+ user
				+ '\''
				+ ", document_id='"
				+ documentId
				+ '\''
				+ '}';
	}
}
