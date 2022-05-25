package com.csvreader.csvtodatabase.repository;

import com.csvreader.csvtodatabase.model.BookModel;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface BookRepository extends MongoRepository<BookModel, String> {
}
