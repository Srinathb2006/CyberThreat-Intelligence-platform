package com.cyberintel.util;
import com.cyberintel.config.AnalysisRuntimeProperties;
import com.cyberintel.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import java.io.*;
import java.nio.file.Path;
import java.util.*;
import java.util.zip.*;
@Component
public class ApkArchiveValidator {
 private final AnalysisRuntimeProperties config;
 public ApkArchiveValidator(AnalysisRuntimeProperties config){this.config=config;}
 public void validate(Path archive){
  try(ZipFile zip=new ZipFile(archive.toFile())){
   var entries=zip.entries();Set<String> names=new HashSet<>();long expanded=0;int count=0;byte[] manifest=null;
   while(entries.hasMoreElements()){
    ZipEntry entry=entries.nextElement();String name=entry.getName();
    if(++count>config.getMaxEntries())bad("APK contains too many archive entries.");
    if(name.length()>512 || name.startsWith("/") || name.contains("\\") || name.contains(":") || name.chars().anyMatch(Character::isISOControl)
     || Arrays.asList(name.split("/")).contains("..") || !names.add(name.toLowerCase(Locale.ROOT)))bad("APK contains an unsafe or duplicate archive path.");
    if(entry.isDirectory())continue;
    if(entry.getSize()<0 || entry.getSize()>config.getMaxExpandedBytes())bad("APK entry exceeds archive limits.");
    if(entry.getSize()>1048576 && entry.getCompressedSize()>0 && entry.getSize()/entry.getCompressedSize()>200)bad("APK compression ratio exceeds the safety limit.");
    CRC32 crc=new CRC32();long size=0;
    boolean isManifest=name.equals("AndroidManifest.xml");ByteArrayOutputStream manifestBytes=isManifest?new ByteArrayOutputStream():null;
    try(var in=zip.getInputStream(entry)){
     byte[] buffer=new byte[8192];int n;
     while((n=in.read(buffer))!=-1){
      expanded+=n;size+=n;
      if(expanded>config.getMaxExpandedBytes())bad("APK expanded size exceeds the safety limit.");
      if(isManifest && size>2097152)bad("Android manifest exceeds the safety limit.");
      crc.update(buffer,0,n);if(isManifest)manifestBytes.write(buffer,0,n);
     }
    }
    if(size!=entry.getSize() || crc.getValue()!=entry.getCrc())bad("APK archive integrity check failed.");
    if(isManifest)manifest=manifestBytes.toByteArray();
   }
   if(manifest==null || manifest.length<8)bad("APK must contain a valid AndroidManifest.xml.");
   if(manifest[0]==3 && manifest[1]==0 && manifest[2]==8 && manifest[3]==0){
    long declared=Integer.toUnsignedLong(java.nio.ByteBuffer.wrap(manifest,4,4).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt());
    if(declared!=manifest.length)bad("Binary Android manifest is corrupted.");
   }else{
    var document=SecureXml.parse(new ByteArrayInputStream(manifest));
    if(!document.getDocumentElement().getTagName().equals("manifest"))bad("APK manifest root is invalid.");
   }
  }catch(ApiException e){throw e;}catch(Exception e){bad("APK is corrupted or contains an invalid Android manifest.");}
 }
 private static void bad(String message){throw new ApiException(HttpStatus.BAD_REQUEST,message);}
}
