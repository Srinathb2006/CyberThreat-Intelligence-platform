package com.cyberintel;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.*;
final class ApkTestFixtures {
 static final String MANIFEST="""
  <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.safe" android:versionCode="3" android:versionName="1.2">
   <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
   <uses-permission android:name="android.permission.CAMERA"/>
   <application android:label="Safe fixture">
    <activity android:name=".MainActivity" android:exported="true"/>
    <service android:name=".PrivateService" android:exported="false"/>
    <receiver android:name=".Receiver" android:exported="false"/>
    <provider android:name=".Provider" android:exported="false"/>
   </application>
  </manifest>
  """;
 static byte[] apk(String extra)throws IOException{
  var bytes=new ByteArrayOutputStream();
  try(var zip=new ZipOutputStream(bytes)){zip.putNextEntry(new ZipEntry("AndroidManifest.xml"));zip.write(MANIFEST.getBytes(StandardCharsets.UTF_8));zip.closeEntry();if(extra!=null){zip.putNextEntry(new ZipEntry(extra));zip.write("fixture".getBytes(StandardCharsets.UTF_8));zip.closeEntry();}}
  return bytes.toByteArray();
 }
}
