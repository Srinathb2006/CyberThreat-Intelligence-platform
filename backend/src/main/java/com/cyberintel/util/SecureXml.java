package com.cyberintel.util;
import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
public final class SecureXml {
 private SecureXml(){}
 public static Document parse(InputStream input)throws Exception{
  var factory=DocumentBuilderFactory.newInstance();factory.setNamespaceAware(true);
  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
  factory.setFeature("http://xml.org/sax/features/external-general-entities",false);
  factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
  factory.setXIncludeAware(false);factory.setExpandEntityReferences(false);
  var builder=factory.newDocumentBuilder();
  builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler(){@Override public void fatalError(org.xml.sax.SAXParseException e)throws org.xml.sax.SAXException{throw e;}});
  return builder.parse(input);
 }
}
