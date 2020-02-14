/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;
import lombok.ToString;

/**
 *
 * @author parashar
 */
@ToString(includeFieldNames=true)
@Data
@AllArgsConstructor
public class SecretKeySpec{

    @NonNull
    String remotePublicKey;
    @NonNull
    String ourPrivateKey;
    //VoYe/aG9m763g2KBE6r6fR+gB7gMTc4hxry9VQhBhdQ=
    public SecretKeySpec() {}
}

