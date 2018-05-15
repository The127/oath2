error_chain!{
    types{
        Error, ErrorKind, ResultExt, Result;
    }

    links {

    }

    foreign_links{
        Io(::std::io::Error);
    }

    errors{
        InvalidSliceLength(expected: usize, actual: usize, ttype: &'static str) {
            description("Invalid slice length received."),
            display("Expected '{}' but got '{}' bytes for '{}'.", expected, actual, ttype),
        }

        UnknownValue(val: u64, ttype: &'static str) {
            description("Encountered unknown value."),
            display("Encountered unknown value '{}' for type '{}.", val, ttype),
        }

        IllegalValue(val: u64, ttype: &'static str) {
            description("Encountered illegal value."),
            display("Encountered illegal value '{}' for type '{}.", val, ttype),
        }
    }
}
