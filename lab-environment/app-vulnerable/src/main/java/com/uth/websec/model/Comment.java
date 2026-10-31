package com.uth.websec.model;

public class Comment {
    private int id;
    private int productId;
    private String author;
    private String content;
    private String createdAt;

    public Comment() {}

    public Comment(int id, int productId, String author, String content, String createdAt) {
        this.id = id;
        this.productId = productId;
        this.author = author;
        this.content = content;
        this.createdAt = createdAt;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getProductId() {
        return productId;
    }

    public void setProductId(int productId) {
        this.productId = productId;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }
}
