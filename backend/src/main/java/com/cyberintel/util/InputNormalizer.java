package com.cyberintel.util;
import java.util.Locale;
public final class InputNormalizer {
 private InputNormalizer(){}
 public static String email(String value){return value.strip().toLowerCase(Locale.ROOT);}
}
