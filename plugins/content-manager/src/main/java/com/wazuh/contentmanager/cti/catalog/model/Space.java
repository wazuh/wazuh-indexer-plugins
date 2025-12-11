package com.wazuh.contentmanager.cti.catalog.model;

import java.util.Locale;

/**
 * Enum class that describes all the possible spaces that the content manager will manage
 */
public enum Space {
    FREE, PAID, CUSTOM, DRAFT, TESTING;

    public String toString() {
        return this.name().toLowerCase(Locale.ROOT);
    }

    public boolean equals(String s) {
        return this.toString().equals(s);
    }
}
