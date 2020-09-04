package pl.gregorymartin.jwtapp1;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/books")
class BookApi {
    private final List<String> bookList;

    public BookApi() {
        this.bookList = new ArrayList<>();
        bookList.add("Book1");
        bookList.add("Book2");
    }

    @GetMapping
    List<String> getBooklist(){
        return bookList;
    }

    @PostMapping
    String setBook(@RequestBody String book){
        bookList.add(book);
        return book;
    }
}
