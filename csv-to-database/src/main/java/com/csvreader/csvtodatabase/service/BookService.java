package com.csvreader.csvtodatabase.service;

import com.csvreader.csvtodatabase.encryptor.PgpEncryptor;
import com.csvreader.csvtodatabase.model.BookModel;
import com.csvreader.csvtodatabase.repository.BookRepository;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.FileReader;

@Service
@RequiredArgsConstructor
public class BookService {

    private final BookRepository bookRepository;
    private final PgpEncryptor encryptor;

    // path of csv file
    @Value("${csv.file-path}")
    private String FILEPATH;


    //    To Encrypt Stream Data received From mongodb
    public void getFileEncrypted() throws Exception {

        var csvMapper = new CsvMapper();

        // Set CsvSchema To withoutQuote Character
        var columns = csvMapper.schemaFor(BookModel.class).withUseHeader(true).withoutQuoteChar();
        var bookList = bookRepository.findAll();
        var byteArrayInputStream = new ByteArrayInputStream(csvMapper.writer(columns).writeValueAsBytes(bookList));


        // Getting Values of byteArrayInputStream in byte Array
        var bytesToEncrypt = byteArrayInputStream.readAllBytes();

//        String s = new String(bytesToEncrypt);
//        String stringToProcess = s.replaceAll("\"", "");

        var encryptedByteArrayOutputStream = encryptor.encryption(bytesToEncrypt);

        System.out.println("File Encrypted successfully");
    }

    // To Store CSV data to mongodb
    public void csvToByteArrayConverter() {

        var bookModelSchema = CsvSchema.emptySchema().withHeader();

        var csvMapper = new CsvMapper();
        var objectReader = csvMapper.readerFor(BookModel.class).with(bookModelSchema);

        try (var fileReader = new FileReader(FILEPATH)) {
            MappingIterator<BookModel> iterator = objectReader.readValues(fileReader);
            var bookModels = iterator.readAll();
            bookRepository.saveAll(bookModels);

        } catch (Exception exception) {
            exception.printStackTrace();
            System.out.println("|| Unable to process the CSV file ||");
        }

    }

}
