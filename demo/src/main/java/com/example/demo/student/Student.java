package com.example.demo.student;

public class Student {

    private Integer id;
    private String studentName;

    public Student(Integer id, String studentName) {
        this.id = id;
        this.studentName = studentName;
    }

    public Integer getId() {
        return id;
    }

    public String getStudentName() {
        return studentName;
    }
}
