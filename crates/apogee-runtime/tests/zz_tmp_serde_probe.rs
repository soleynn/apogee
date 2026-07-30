//! temporary probe, delete me
use apogee_runtime::{Gamescope, GpuSelect, Hud, SyncChoice};

#[test]
fn probe() {
    println!(
        "sync auto = {}",
        serde_json::to_string(&SyncChoice::Auto).unwrap()
    );
    println!(
        "sync ntsync = {}",
        serde_json::to_string(&SyncChoice::Ntsync).unwrap()
    );
    println!(
        "hud none = {}",
        serde_json::to_string(&Hud::None).unwrap()
    );
    println!(
        "hud dxvk = {}",
        serde_json::to_string(&Hud::Dxvk("fps,frametimes".into())).unwrap()
    );
    println!(
        "hud mango = {}",
        serde_json::to_string(&Hud::Mango).unwrap()
    );
    println!(
        "gpu default = {}",
        serde_json::to_string(&GpuSelect::Default).unwrap()
    );
    println!(
        "gpu nvidia = {}",
        serde_json::to_string(&GpuSelect::NvidiaPrime).unwrap()
    );
    println!(
        "gpu vulkan = {}",
        serde_json::to_string(&GpuSelect::VulkanDevice("10de:2482".into())).unwrap()
    );
    println!(
        "gamescope = {}",
        serde_json::to_string(&Gamescope::default()).unwrap()
    );

    // round trips
    let h = Hud::Dxvk("fps".into());
    let s = serde_json::to_string(&h).unwrap();
    assert_eq!(serde_json::from_str::<Hud>(&s).unwrap(), h);
    let g = GpuSelect::VulkanDevice("10de:2482".into());
    let s = serde_json::to_string(&g).unwrap();
    assert_eq!(serde_json::from_str::<GpuSelect>(&s).unwrap(), g);

    // partial gamescope object
    let partial = serde_json::from_str::<Gamescope>(r#"{"fullscreen":true}"#);
    println!("partial gamescope = {partial:?}");

    // partial with only options omitted
    let partial2 = serde_json::from_str::<Gamescope>(
        r#"{"width":1920,"height":1080,"refresh":null,"fullscreen":true,"hdr":false}"#,
    );
    println!("partial2 gamescope = {partial2:?}");

    // hud spelled with the rust name
    println!("hud Dxvk pascal = {:?}", serde_json::from_str::<Hud>(r#"{"Dxvk":"fps"}"#));
    println!("gpu NvidiaPrime pascal = {:?}", serde_json::from_str::<GpuSelect>(r#""NvidiaPrime""#));
}
