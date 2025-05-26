use std::{env, fs, path::PathBuf, process::Command, time::SystemTime};
use glob::glob;

const INCLUDE_DIRS: [&str; 2] = ["include", "src"];

struct Builder<'a> {
    // project_dir: PathBuf,
    lib_dir_str: &'a str,
    clib_dir: Option<PathBuf>,
}

// `eprintln!` here is used to see printed text when running with `-vv` flag.

impl<'a> Builder<'a> {
    fn update_clib(&mut self) -> bool {
        let time_before = SystemTime::now();
        let exit_status = Command::new("git")
            .arg("pull")
            .current_dir(self.lib_dir_str)
            .status()
            .unwrap();
        eprintln!("Updated CLib repository, exit status: {exit_status}");
        let time_after = fs::metadata(self.lib_dir_str).unwrap().modified().unwrap();
        time_after > time_before
    }

    fn build_clib(&mut self) {
        eprintln!("Building CLib to {:?}", self.clib_dir);
        let bee2_c = if let Some(dir) = self.clib_dir.as_ref() {
            cmake::Config::new("bee2-c").out_dir(dir.join("cmake")) .build()
        } else {
            let result = cmake::build("bee2-c");
            self.clib_dir = Some(result.clone());
            result
        };
        let bee2_c_str = bee2_c.to_str().unwrap();
        eprintln!("Builded CLib to {bee2_c_str}");
    }

    fn generate_bindings_source(&mut self) {
        let Some(clib_dir) = self.clib_dir.as_ref() else {
            return;
        };
        let mut bindings = bindgen::Builder::default()
            .header(clib_dir.join("bindings.h").to_str().unwrap().to_owned())
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate_comments(false);

        for include_dir in INCLUDE_DIRS {
            bindings = bindings.clang_arg(format!("-I{}/{include_dir}", self.lib_dir_str));
        }

        let bindings = bindings
            .generate()
            .unwrap();

        bindings.write_to_file(clib_dir.join("bindings.rs")).unwrap();
        eprintln!("Generated bindings source to {:?}", clib_dir.join("bindings.rs"));
    }

    fn generate_bindings_header(&mut self) -> bool {
        let Some(clib_dir) = self.clib_dir.as_ref() else {
            return false;
        };
        let glob_result = glob(
            &format!("{}/**/*.h", self.lib_dir_str)
        );
        let header_files: Vec<String> = glob_result.unwrap().map(|entry| {
            entry.unwrap().to_str().unwrap().to_owned()
        }).collect();

        let mut content: String = String::new();
        content += "#include \"";
        content += &header_files.join("\"\n#include \"");
        content += "\"";
        let header_path = clib_dir.join("bindings.h").to_str().unwrap().to_owned();

        if !fs::exists(&header_path).unwrap_or(true) || content != String::from_utf8(
            fs::read(&header_path).unwrap()
        ).unwrap() {
            fs::write(&header_path, content).unwrap();
            eprintln!("Generated bindings header to {header_path}");
            true
        } else {
            false
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=target/MUST_NOT_EXIST");
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib_dir = project_dir.join("bee2-c");
    let lib_dir_str = lib_dir.to_str().unwrap();

    let mut builder = Builder {
        // project_dir: project_dir.clone(),
        lib_dir_str,
        clib_dir: Some(project_dir.join("target").join("build")),
    };

    let clib_force_rebuild = builder.update_clib();
    println!(
        "cargo:rustc-link-search=native={}/lib",
        builder.clib_dir.as_ref().unwrap().join("cmake").to_str().unwrap(),
    );
    println!("cargo:rustc-link-lib=static=bee2_static");

    let clib_rebuilt = if clib_force_rebuild || (builder.clib_dir.is_some() && !fs::exists(
        builder.clib_dir.as_ref().unwrap()
    ).unwrap_or(false)) {
        fs::create_dir_all(builder.clib_dir.as_ref().unwrap().join("cmake")).unwrap();
        builder.build_clib();
        true
    } else {
        false
    };

    let force_regen_bindings = builder.generate_bindings_header();

    if force_regen_bindings ||
        clib_rebuilt ||
        !fs::exists(builder.clib_dir.as_ref().unwrap().join("bindings.rs")).unwrap_or(false) {
            builder.generate_bindings_source();
    }
}
