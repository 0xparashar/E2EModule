/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.dto;

import lombok.Data;
import lombok.NonNull;
import lombok.ToString;
import org.springframework.lang.Nullable;

/**
 *
 * @author parashar
 */
@ToString(includeFieldNames=true)
@Data
public class SerializedDecryptedData {
    @NonNull
    final private String data;
    @Nullable
    ErrorInfo errorInfo;
}
