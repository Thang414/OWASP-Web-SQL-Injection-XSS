package com.uth.websec.model;

public class Product {
    private String id;
    private String name;
    private String description;
    private String price;
    private String category;

    public Product() {}

    public Product(String id, String name, String description, String price, String category) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.price = price;
        this.category = category;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getPrice() {
        return price;
    }

    public void setPrice(String price) {
        this.price = price;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getFormattedPrice() {
        if (price == null || price.trim().isEmpty()) {
            return "0 VNĐ";
        }
        try {
            double p = Double.parseDouble(price);
            return String.format("%,.0f VNĐ", p).replace(',', '.');
        } catch (NumberFormatException e) {
            // Trường hợp SQL Injection Union-based trích xuất dữ liệu thẻ tín dụng hoặc mật khẩu vào cột price
            return price;
        }
    }
}
