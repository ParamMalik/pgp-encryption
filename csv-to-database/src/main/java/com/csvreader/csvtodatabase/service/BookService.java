package com.csvreader.csvtodatabase.service;

import com.csvreader.csvtodatabase.encryptor.PgpEncryptor;
import com.csvreader.csvtodatabase.model.BookModel;
import com.csvreader.csvtodatabase.repository.BookRepository;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.util.List;

@Service
@RequiredArgsConstructor
public class BookService {

    private final BookRepository bookRepository;
    private final PgpEncryptor encryptor;

    // path of csv file
    private static final String FILEPATH = "src/main/resources/byteDataFromCsvFile.csv";

    // public key for testing
    private static final String PUBLIC_KEY_FILE = "src/main/resources/PublicKey.asc";
//    private static final String PUBLIC_KEY_FILE = "src/main/resources/ClientKey.asc";


    //    To Encrypt Stream Data received From mongodb
    public void getFileEncrypted() throws Exception {

        CsvMapper csvMapper = new CsvMapper();
        CsvSchema columns = csvMapper.schemaFor(BookModel.class).withUseHeader(true);
        List<BookModel> bookList = bookRepository.findAll();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(csvMapper.writer(columns).writeValueAsBytes(bookList));

        int availableSize = byteArrayInputStream.available();

        byte[] bytes = new byte[availableSize];
        byteArrayInputStream.read(bytes);


        encryptor.encryption(bytes, PUBLIC_KEY_FILE);
        System.out.println("File Encrypted successfully");
    }

    // To Store CSV data to mongodb
    public void csvToByteArrayConverter() {

        CsvSchema bookModelSchema = CsvSchema.emptySchema().withHeader();

        CsvMapper csvMapper = new CsvMapper();
        ObjectReader objectReader = csvMapper.readerFor(BookModel.class).with(bookModelSchema);

        try (FileReader fileReader = new FileReader(FILEPATH)) {
            MappingIterator<BookModel> iterator = objectReader.readValues(fileReader);
            List<BookModel> bookModels = iterator.readAll();
            bookRepository.saveAll(bookModels);

        } catch (Exception exception) {
            exception.printStackTrace();
            System.out.println("|| Unable to process the CSV file ||");
        }

    }

}
