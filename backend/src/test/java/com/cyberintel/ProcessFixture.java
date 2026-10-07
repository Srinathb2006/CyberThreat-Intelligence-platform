package com.cyberintel;
public class ProcessFixture {
 public static void main(String[] args)throws Exception{
  if(args.length>0&&args[0].equals("sleep"))Thread.sleep(30000);
  System.out.println("fixture output");System.err.println("fixture stderr");
 }
}
