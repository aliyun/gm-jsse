package com.aliyun.gmsse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

public class ClientRandom {
  public int gmtUnixTime;
  public byte[] randomBytes;

  public ClientRandom(int gmtUnixTime, byte[] randomBytes) {
    this.gmtUnixTime = gmtUnixTime;
    this.randomBytes = randomBytes;
  }

  public byte[] getBytes() throws IOException {
    ByteArrayOutputStream ba = new ByteArrayOutputStream();
    ba.write((gmtUnixTime >>> 24) & 0xFF);
    ba.write((gmtUnixTime >>> 16) & 0xFF);
    ba.write((gmtUnixTime >>> 8) & 0xFF);
    ba.write(gmtUnixTime & 0xFF);
    ba.write(randomBytes);
    return ba.toByteArray();
  }

    @Override
    public String toString()
    {
      StringWriter str = new StringWriter();
      PrintWriter out = new PrintWriter(str);
      out.println("struct {");
      out.println("  gmt_unix_time = " + gmtUnixTime + ";");
      out.println("  random_bytes = " + Util.hexString(randomBytes) + ";");
      out.println("} Random;");
      return str.toString();
    }

}