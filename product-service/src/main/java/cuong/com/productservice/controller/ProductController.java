package cuong.com.productservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    public record Product(Long id, String name, Double price) {}

    // Dữ liệu tĩnh giả lập danh sách sản phẩm
    private final List<Product> products = new ArrayList<>(List.of(
            new Product(1L, "Laptop Dell G15 5511", 22500000.0),
            new Product(2L, "Tai nghe Bluetooth Edifier W826NB", 1150000.0),
            new Product(3L, "Bàn phím cơ không dây", 1800000.0)
    ));

    // Cho phép mọi user đã đăng nhập (có Token hợp lệ) truy cập
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<Product>> getAllProducts() {
        return ResponseEntity.ok(products);
    }

    // Chỉ cho phép User có Role ADMIN thực hiện
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) {
        boolean removed = products.removeIf(p -> p.id().equals(id));
        if (!removed) {
            return ResponseEntity.status(404).body(Map.of("message", "Không tìm thấy sản phẩm với ID: " + id));
        }
        return ResponseEntity.ok(Map.of(
                "message", "Đã xóa thành công sản phẩm có ID: " + id,
                "remainingProducts", products
        ));
    }
}