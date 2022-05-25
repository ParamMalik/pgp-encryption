package com.csvreader.csvtodatabase.controller;

import com.csvreader.csvtodatabase.service.BookService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/file")
public class AppController {
    private final BookService service;

    @GetMapping("/save")
    public ResponseEntity<String> getFile() throws Exception {
//        service.csvToByteArrayConverter();

        service.getFileEncrypted();
        return new ResponseEntity<>("Done", HttpStatus.ACCEPTED);
    }

}
