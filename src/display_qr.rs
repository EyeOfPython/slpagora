use qrcode::QrCode;
use std::iter;

pub fn display(data: &[u8]) {

    let code = match QrCode::new(data) {
        Ok(code) => code,
        Err(_) => {
            return;
        }
    };

    let string = code.render()
        .light_color(' ')
        .dark_color('#')
        .build();

    let mut empty_str: String;
    let mut line_buffer = String::new();
    let mut lines = string.lines().into_iter();

    while let Some(line_top) = lines.next() {
        let line_bottom = match lines.next() {
            Some(l) => l,
            None => {
                empty_str = iter::repeat(' ').take(line_top.len()).collect();
                empty_str.as_str()
            }
        };

        for (top, bottom) in line_top.chars().zip(line_bottom.chars()) {
            let block = match (top, bottom) {
                ('#', '#') => '█',
                (' ', '#') => '▄',
                ('#', ' ') => '▀',
                _ => ' ',
            };
            line_buffer.push(block);
        }

        println!("{}", line_buffer);
        line_buffer.clear();
    }
}
