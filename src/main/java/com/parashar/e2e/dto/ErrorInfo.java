/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.dto;

import lombok.Data;
import lombok.ToString;
import org.springframework.lang.Nullable;

/**
 *
 * @author parashar
 */
@ToString(includeFieldNames=true)
@Data
public class ErrorInfo{
    @Nullable 
    private String errorCode;
    @Nullable
    private String errorMessage;
    @Nullable
    private ErrorInfo errorInfo; 
}
