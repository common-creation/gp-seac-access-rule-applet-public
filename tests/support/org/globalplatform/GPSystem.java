/*
 * Copyright 2025-2026 COMMON CREATION, Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.globalplatform;

/** Simulator-only service. Never included in a CAP. No cryptography is tested here. */
public final class GPSystem {
    public static final SecureChannel CHANNEL = new SecureChannel();
    public static SecureChannel getSecureChannel() { return CHANNEL; }
}
