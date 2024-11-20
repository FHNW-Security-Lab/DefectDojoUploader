# AFL Triage and DefectDojo Integration

This system helps you analyze AFL fuzzing crashes and automatically upload the results to DefectDojo. It combines AFLTriage for crash analysis with a custom uploader for DefectDojo integration.

## Prerequisites

- LibAFL generated crashes
- A test binary for crash validation
- Running DefectDojo instance with API access
- Rust (for building AFLTriage)
- Python 3.x (for the DefectDojo uploader)

## System Components

1. **AFLTriage**: A Rust-based tool for analyzing and deduplicating crashes from AFL-style fuzzers
2. **DefectDojo Uploader**: A Python script to automatically upload triage results to DefectDojo

## Installation

### 1. Install AFLTriage

```bash
# Clone the AFLTriage repository
git clone https://github.com/quic/AFLTriage.git

# Build AFLTriage
cd AFLTriage
cargo build --release

# The binary will be available in target/release/afltriage
cd ..
```

### 2. Install DefectDojo Uploader

```bash
# Clone the DefectDojo uploader repository
git clone https://github.com/FHNW-Security-Lab/DefectDojoUploader
```

### 3. Configure DefectDojo Integration

Create a `dojo.toml` file in your workspace directory with the following content:

```toml
[product]
name = "<program-name>"      # Add product name 
type = "<product-type>"      # Add product type 

[engagement]
name = "engagement-name" 
target_start = "<...>"       # Added start date
target_end = "<...>"         # Added end date

[test]
test_type = "<test-type>"    # add test type 
target_start = "..."         # Added start date
target_end = "..."           s# Added end date
```

Replace the placeholder values:
- `program-name`: Name of your product in DefectDojo
- `product-type`: Type of the product (e.g., "Application")
- `engagement-name`: Name of the engagement in DefectDojo
- `test-type`: Type of test (e.g., "Fuzzing Test")

## Directory Structure

Your workspace should look like this:

```
.
├── crashes/                # Directory containing LibAFL crashes
├── testerbinary            # Your binary for crash validation
├── AFLTriage/              # AFLTriage installation
└── DefectDojoUploader      # DefectDojo uploader scripts
```

## Usage

### 1. Running AFLTriage

Choose one of the following commands based on your binary's input method:

#### For programs that read from stdin:
```bash
./AFLTriage/target/release/afltriage --stdin -i ./crashes -o triage ./testerbinary
```

#### For programs that read from a file (using @@ notation):
```bash
./AFLTriage/target/release/afltriage -i ./crashes -o triage ./testerbinary @@
```

This will analyze all crashes and generate a triage report in the `triage` directory.

### 2. Uploading to DefectDojo

```bash
python3 DefectDojoUploader/upload_defect_dojo.py \
    --token <api_key_defect_dojo> \
    --host https://<defect_dojo_host> \
    --triage-dir triage
```

Replace the following placeholders:
- `<api_key_defect_dojo>`: Your DefectDojo API key
- `<defect_dojo_host>`: Your DefectDojo instance hostname


### Getting Help

- For AFLTriage issues: Visit the [AFLTriage GitHub repository](https://github.com/quic/AFLTriage)
- For DefectDojo API issues: Consult the [DefectDojo API documentation](https://defectdojo.readthedocs.io/en/latest/api-v2-docs.html)

## Contributing

Feel free to submit issues and enhancement requests for either component:
- AFLTriage: Through the official GitHub repository
- DefectDojo Uploader: Through this repository's issue tracker

## License

- AFLTriage: Check the [AFLTriage repository](https://github.com/quic/AFLTriage) for license information
- DefectDojo Uploader: BSD-3-Clause License

## Security Notes

- Keep your DefectDojo API key secure
- Don't share crash dumps containing sensitive information
- Review crashes before uploading to DefectDojo
- Consider network security when setting up DefectDojo integration
