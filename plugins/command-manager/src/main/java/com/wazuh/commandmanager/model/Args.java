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

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Handles the command.action.args object */
public class Args implements ToXContentObject {

  public static final String ARGS = "args";
  private final Map<String, Object> args;

  /** Parameterless constructor. */
  public Args() {
    this.args = new HashMap<>();
  }

  /**
   * Constructor with parameters.
   *
   * @param args Initializes the args object
   */
  public Args(Map<String, Object> args) {
    this.args = new HashMap<>(args);
  }

  /**
   * Generic command.action.args parser.
   *
   * @param parser An XContentParser containing an args to be deserialized
   * @return An Args object
   * @throws IOException Rethrows the exception from list() and objectText() method
   */
  public static Args parse(XContentParser parser) throws IOException {
    Map<String, Object> args = new HashMap<>();

    String fieldName = "";
    List<Object> list = null;
    boolean isList = false;

    while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
      XContentParser.Token actualToken = parser.currentToken();
      switch (actualToken) {
        case FIELD_NAME:
          fieldName = parser.currentName();
          break;
        case START_ARRAY:
          list = new ArrayList<>();
          isList = true;
          break;
        case VALUE_STRING:
          if (isList) {
            list.add(parser.objectText());
          } else {
            args.put(fieldName, parser.objectText());
          }
          break;
        case VALUE_NUMBER:
          if (isList) {
            list.add(parser.numberValue());
          } else {
            args.put(fieldName, parser.numberValue());
          }
          break;
        case VALUE_NULL:
          if (isList) {
            list.add("");
          } else {
            args.put(fieldName, "");
          }
          break;
        case END_ARRAY:
          args.put(fieldName, list);
          list = null;
          isList = false;
          break;
        case START_OBJECT:
          args.put(fieldName, Args.parse(parser).getArgs());
          break;
        default:
          break;
      }
    }
    return new Args(args);
  }

  /**
   * Required for the parsing of nested objects.
   *
   * @return internal args map.
   */
  public Map<String, Object> getArgs() {
    return this.args;
  }

  /**
   * Builds an Args XContentBuilder. Iterates over the args map adding key-value pairs
   *
   * @param builder This is received from the parent object
   * @param params Not used
   * @return A complete args XContentBuilder object
   * @throws IOException rethrown from XContentBuilder objects within
   */
  @Override
  public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
    builder.startObject(Args.ARGS);
    for (String key : this.args.keySet()) {
      builder.field(key, this.args.get(key));
    }
    return builder.endObject();
  }

  /**
   * @return a String representation of the contents of the Args object
   */
  @Override
  public String toString() {
    return "Args{" + "args='" + args + '\'' + '}';
  }
}
