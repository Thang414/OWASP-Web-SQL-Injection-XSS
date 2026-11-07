package com.uth.websec.model;

public class Product {
    private String id;
    private String name;
    private String description;
    private String price;
    private String category;
    private String imageUrl;

    public Product() {}

    public Product(String id, String name, String description, String price, String category) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.price = price;
        this.category = category;
    }

    public Product(String id, String name, String description, String price, String category, String imageUrl) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.price = price;
        this.category = category;
        this.imageUrl = imageUrl;
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

    public String getImageUrl() {
        if (imageUrl != null && !imageUrl.trim().isEmpty()) {
            return imageUrl;
        }
        if (name == null) {
            return "/images/products/default-device.svg";
        }
        String lower = name.toLowerCase();
        if (lower.contains("iphone")) {
            return "/images/products/iphone-15-pro-max.jpg";
        } else if (lower.contains("samsung") || lower.contains("s24")) {
            return "/images/products/samsung-s24-ultra.jpg";
        } else if (lower.contains("dell") || lower.contains("xps")) {
            return "/images/products/dell-xps-15.png";
        } else if (lower.contains("macbook")) {
            return "/images/products/macbook-air-m2.jpg";
        } else if (lower.contains("sony") || lower.contains("wh-1000") || lower.contains("tai nghe")) {
            return "/images/products/sony-wh1000xm5.jpg";
        }
        return "/images/products/default-device.svg";
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
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
