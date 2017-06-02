package com.nitorcreations.vault;

import java.security.GeneralSecurityException;

public class VaultException extends Exception {
  public VaultException(String message, GeneralSecurityException cause) {
    super(message, cause);
  }
}
