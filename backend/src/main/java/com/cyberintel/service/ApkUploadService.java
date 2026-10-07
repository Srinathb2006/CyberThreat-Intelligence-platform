package com.cyberintel.service;
import com.cyberintel.config.AnalysisProperties;
import com.cyberintel.dto.ApkDtos.UploadResponse;
import com.cyberintel.util.*;
import com.cyberintel.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
@Service
public class ApkUploadService {
 private final ApkUploadValidator transport;private final ApkArchiveValidator archive;private final AnalysisStorage storage;private final ApkAnalysisState state;private final AnalysisProperties config;
 public ApkUploadService(ApkUploadValidator transport,ApkArchiveValidator archive,AnalysisStorage storage,ApkAnalysisState state,AnalysisProperties config){this.transport=transport;this.archive=archive;this.storage=storage;this.state=state;this.config=config;}
 public UploadResponse upload(MultipartFile file,String email){
  transport.validate(file);AnalysisStorage.Stored stored=null;
  try(var input=file.getInputStream()){
   stored=storage.store(input,config.getMaxApkSize().toBytes());archive.validate(storage.upload(stored.key()));
   return state.create(email,file.getOriginalFilename(),stored);
  }catch(Exception e){
   if(stored!=null)try{storage.deleteUpload(stored.key());}catch(IOException ignored){}
   if(e instanceof RuntimeException runtime)throw runtime;
   throw new ApiException(HttpStatus.INSUFFICIENT_STORAGE,"Unable to store APK. Check server storage capacity and permissions.");
  }
 }
}
