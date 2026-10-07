package com.cyberintel.util;
import com.cyberintel.config.AnalysisProperties;
import com.cyberintel.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.Locale;
/** Transport checks; ApkArchiveValidator validates archive contents after bounded storage. */
@Component
public class ApkUploadValidator {
 private final AnalysisProperties properties;
 public ApkUploadValidator(AnalysisProperties properties){this.properties=properties;}
 public void validate(MultipartFile file){
  String name=file.getOriginalFilename();
  if(name==null || name.length()>255 || name.contains(":") || name.contains("/") || name.contains("\\") || name.chars().anyMatch(Character::isISOControl)
   || !name.toLowerCase(Locale.ROOT).endsWith(".apk"))
   throw new ApiException(HttpStatus.BAD_REQUEST,"A valid .apk filename is required.");
  if(file.isEmpty())throw new ApiException(HttpStatus.BAD_REQUEST,"APK file must not be empty.");
  String mime=file.getContentType();
  if(mime!=null && !java.util.Set.of("application/vnd.android.package-archive","application/octet-stream","application/zip","application/x-zip-compressed").contains(mime.toLowerCase(Locale.ROOT).split(";")[0]))
   throw new ApiException(HttpStatus.BAD_REQUEST,"Unsupported APK content type.");
  if(file.getSize()>properties.getMaxApkSize().toBytes())throw new ApiException(HttpStatus.PAYLOAD_TOO_LARGE,"APK exceeds the configured size limit.");
  try(var input=file.getInputStream()){
   byte[] signature=input.readNBytes(4);
   if(signature.length!=4 || signature[0]!=0x50 || signature[1]!=0x4b || signature[2]!=0x03 || signature[3]!=0x04)
    throw new ApiException(HttpStatus.BAD_REQUEST,"APK must be a ZIP-format archive.");
  }catch(IOException e){throw new ApiException(HttpStatus.BAD_REQUEST,"Unable to read uploaded file.");}
 }
}
