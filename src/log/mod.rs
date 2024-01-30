use colored::Colorize;

pub fn info(message: &str) {
    println!("{} {}", "[INFO]".green(), message);
}

pub fn warning(message: &str) {
    println!("{} {}", "[WARNING]".yellow(), message);
}

pub fn error(message: &str) {
    println!("{} {}", "[ERROR]".red(), message);
}

