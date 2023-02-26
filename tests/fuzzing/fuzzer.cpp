#include <stdexcept>
#include <unistd.h>

#include <document.h>
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>
#include <sstream>
#include <thread>
#include <valijson/adapters/rapidjson_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/utils/rapidjson_utils.hpp>

using valijson::Schema;
using valijson::SchemaParser;
using valijson::adapters::RapidJsonAdapter;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t kMaxSchemaFileSize = 1024;
    FuzzedDataProvider fdp(data, size);
    if (size < 3)
        return 0;
    // Create a file per thread so that the fuzzer can be run in parralell.
    char schema_input_file[256];
    sprintf(schema_input_file, "/tmp/libfuzzer-%zu.json",
            std::hash<std::thread::id>{}(std::this_thread::get_id()));
    FILE *schema_fp = fopen(schema_input_file, "wb");

    char to_validate_input_file[256];
    sprintf(to_validate_input_file, "/tmp/libfuzzer-to-validate-%zu.json",
            std::hash<std::thread::id>{}(std::this_thread::get_id()));
    FILE *to_validate_fp = fopen(to_validate_input_file, "wb");
    if (!schema_fp || !to_validate_fp) {
        return 0;
    }
    {
        std::vector<uint8_t> schema_data = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<int>(0, kMaxSchemaFileSize));
        fwrite(schema_data.data(), schema_data.size(), 1, schema_fp);

        std::vector<uint8_t> to_validate = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<int>(0, kMaxSchemaFileSize));
        fwrite(to_validate.data(), to_validate.size(), 1, schema_fp);
    }
    fclose(schema_fp);
    fclose(to_validate_fp);

    rapidjson::Document schemaDocument;
    if (!valijson::utils::loadDocument(schema_input_file, schemaDocument)) {
        return 1;
    }

    Schema schema;
    SchemaParser parser;
    RapidJsonAdapter schemaDocumentAdapter(schemaDocument);
    try {
        parser.populateSchema(schemaDocumentAdapter, schema);
    } catch (std::exception &e) {
        unlink(schema_input_file);
        unlink(to_validate_input_file);
        return 1;
    }

    rapidjson::Document myTargetDoc;
    if (!valijson::utils::loadDocument(to_validate_input_file, myTargetDoc)) {
        return 1;
    }

    unlink(schema_input_file);
    unlink(to_validate_input_file);
    return 1;
}
