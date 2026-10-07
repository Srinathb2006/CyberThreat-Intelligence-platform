package com.cyberintel;
import com.cyberintel.config.AnalysisProperties;
import com.cyberintel.util.ApkUploadValidator;
import com.cyberintel.exception.ApiException;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.util.unit.DataSize;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class ApkUploadValidatorTest {
 @Test void checksFilenameSizeAndSignature(){
  var properties=new AnalysisProperties();properties.setMaxApkSize(DataSize.ofBytes(8));var validator=new ApkUploadValidator(properties);
  byte[] zip={0x50,0x4b,0x03,0x04};
  assertThatCode(()->validator.validate(new MockMultipartFile("file","sample.apk","application/octet-stream",zip))).doesNotThrowAnyException();
  for(String name:new String[]{"../sample.apk","sample.exe","a\\sample.apk"}){
   assertThatThrownBy(()->validator.validate(new MockMultipartFile("file",name,"application/octet-stream",zip))).isInstanceOf(ApiException.class);
  }
  assertThatThrownBy(()->validator.validate(new MockMultipartFile("file","sample.apk","application/octet-stream",new byte[10]))).isInstanceOf(ApiException.class);
  assertThatThrownBy(()->validator.validate(new MockMultipartFile("file","sample.apk","application/octet-stream","fake".getBytes()))).isInstanceOf(ApiException.class);
 }
}
