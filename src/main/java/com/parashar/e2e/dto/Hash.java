/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.dto;

/**
 *
 * @author parashar
 */
public enum Hash {
    SHA256("HmacSHA256", 32),
    SHA1("HmacSHA1", 20);
    // MD5 intentionally omitted

    private final String algorithm;
    private final int byteLength;

    Hash(String algorithm, int byteLength) {
      if (byteLength <= 0) {
        throw new IllegalArgumentException("byteLength must be positive");
      }
      this.algorithm = algorithm;
      this.byteLength = byteLength;
    }

    /**
     * @return JCA-recognized algorithm name.
     */
    public String getAlgorithm() {
      return algorithm;
    }

    /**
     * @return length of HMAC output in bytes.
     */
    public int getByteLength() {
      return byteLength;
    }
}
