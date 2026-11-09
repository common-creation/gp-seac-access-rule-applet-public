/*
 * Copyright 2025-2026 COMMON CREATION, Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.common_creation.applet.gp_ara_d;

import com.common_creation.applet.ara.AccessRuleApplet;

/** ARA-D access rules. */
public final class ARADApplet extends AccessRuleApplet {
    private ARADApplet(byte[] parameters, short offset, byte length) {
        super(false, parameters, offset, length);
    }

    public static void install(byte[] parameters, short offset, byte length) {
        new ARADApplet(parameters, offset, length);
    }
}
