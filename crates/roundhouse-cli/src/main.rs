#![forbid(unsafe_code)]

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let _schema = roundhouse_tui::client_schema();
    Ok(())
}
