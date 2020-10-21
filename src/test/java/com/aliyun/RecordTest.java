package com.aliyun;

import com.aliyun.gmsse.Record;
import com.aliyun.gmsse.Record.ContentType;
import org.junit.Assert;
import org.junit.Test;

public class RecordTest {

    @Test
    public void getInstanceTest() {
        ContentType contentType = Record.ContentType.getInstance(24);
        Assert.assertEquals("content type: site2site", contentType.toString());
    }
}
