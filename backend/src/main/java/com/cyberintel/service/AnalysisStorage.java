package com.cyberintel.service;
import com.cyberintel.config.*;
import com.cyberintel.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.util.*;
@Service
public class AnalysisStorage {
 private final Path root,uploads;
 public AnalysisStorage(AnalysisRuntimeProperties properties,AnalysisProperties app)throws IOException{
  root=Path.of(properties.getDirectory()).toAbsolutePath().normalize();uploads=Path.of(app.getUploadDirectory()).toAbsolutePath().normalize();
  safeDirectory(root);safeDirectory(uploads);safeDirectory(root.resolve("scans"));
 }
 public Path upload(String key){if(!key.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("Invalid storage identifier");return checked(uploads.resolve(key+".apk"));}
 public Path scan(long id)throws IOException{if(id<1)throw new IllegalArgumentException("Invalid scan identifier");Path p=checked(root.resolve("scans").resolve(Long.toString(id)));safeDirectory(p);return p;}
 public Path area(long id,String name)throws IOException{
  if(!Set.of("jadx","apktool","aapt","androguard","extracted","temporary").contains(name))throw new IllegalArgumentException("Invalid analysis area");
  Path path=scan(id).resolve(name);safeDirectory(path);return checked(path);
 }
 public Path checked(Path path){
  Path absolute=path.toAbsolutePath().normalize();
  if(!absolute.startsWith(root)&&!absolute.startsWith(uploads))throw new IllegalArgumentException("Outside controlled storage");
  for(Path p=absolute;p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IllegalArgumentException("Symbolic links are forbidden in analysis storage");
  return absolute;
 }
 private void safeDirectory(Path path)throws IOException{
  for(Path p=path;p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Analysis directory must not contain symbolic links");
  Files.createDirectories(path);
 }
 public record Stored(String key,long size,String sha256,String md5){}
 public Stored store(InputStream input,long max)throws IOException{
  String key=UUID.randomUUID().toString();Path destination=upload(key);
  try{
   MessageDigest sha=MessageDigest.getInstance("SHA-256"),md5=MessageDigest.getInstance("MD5");long count=0;
   try(var out=Files.newOutputStream(destination,StandardOpenOption.CREATE_NEW)){
    byte[] buffer=new byte[8192];int n;
    while((n=input.read(buffer))!=-1){count+=n;if(count>max)throw new ApiException(HttpStatus.PAYLOAD_TOO_LARGE,"APK exceeds the configured size limit.");sha.update(buffer,0,n);md5.update(buffer,0,n);out.write(buffer,0,n);}
   }
   return new Stored(key,count,HexFormat.of().formatHex(sha.digest()),HexFormat.of().formatHex(md5.digest()));
  }catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
  catch(IOException|RuntimeException e){Files.deleteIfExists(destination);throw e;}
 }
 public void deleteUpload(String key)throws IOException{Files.deleteIfExists(upload(key));}
 public void cleanTemporary(long id)throws IOException{deleteTree(scan(id).resolve("temporary"));}
 public void deleteArtifacts(long id,String key)throws IOException{deleteTree(root.resolve("scans").resolve(Long.toString(id)));deleteUpload(key);}
 private void deleteTree(Path directory)throws IOException{
  Path safe=checked(directory);
  if(safe.equals(root)||safe.equals(uploads)||safe.equals(root.resolve("scans")))throw new IOException("Refusing to remove storage root");
  if(!Files.exists(safe,LinkOption.NOFOLLOW_LINKS))return;
  Files.walkFileTree(safe,new SimpleFileVisitor<>(){
   @Override public FileVisitResult visitFile(Path file,BasicFileAttributes attrs)throws IOException{Files.delete(file);return FileVisitResult.CONTINUE;}
   @Override public FileVisitResult postVisitDirectory(Path dir,IOException failure)throws IOException{if(failure!=null)throw failure;Files.delete(dir);return FileVisitResult.CONTINUE;}
  });
 }
}
