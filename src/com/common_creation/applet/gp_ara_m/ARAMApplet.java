/*
 * Copyright 2025-2026 COMMON CREATION, Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.common_creation.applet.gp_ara_m;

import com.common_creation.applet.ara.AccessRuleApplet;

/** ARA-M access rules. */
public final class ARAMApplet extends AccessRuleApplet {
    private ARAMApplet(byte[] parameters, short offset, byte length) {
        super(true, parameters, offset, length);
    }

    public static void install(byte[] parameters, short offset, byte length) {
        new ARAMApplet(parameters, offset, length);
    }
}
