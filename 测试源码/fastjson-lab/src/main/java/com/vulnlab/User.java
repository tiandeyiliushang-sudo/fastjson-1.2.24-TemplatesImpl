package com.vulnlab;

/**
 * 用户类 - 正常业务类
 * 用于正常请求时的反序列化
 */
public class User {
    private String name;
    private int age;
    private String email;

    public User() {
        System.out.println("[User] 构造方法被调用");
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        System.out.println("[User] setName: " + name);
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        System.out.println("[User] setAge: " + age);
        this.age = age;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        System.out.println("[User] setEmail: " + email);
        this.email = email;
    }

    @Override
    public String toString() {
        return "User{name='" + name + "', age=" + age + ", email='" + email + "'}";
    }
}
