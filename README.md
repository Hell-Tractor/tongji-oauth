# Tongji Oauth

[![LICENSE](https://img.shields.io/github/license/Hell-Tractor/tongji-oauth)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/tongji-oauth)](https://crates.io/crates/tongji-oauth)

一个用于完成同济大学统一身份认证的Rust语言SDK

## Usage

```rust
use tongji_oauth::Client;

async fn func() {
    let client = Client::new();
    let session_id = client.login("username", "password").await.unwrap();

    // do whatever you want
    let reqwest_client = &client.client;
}
```

## Announcement

本项目仅供学习交流使用，请勿利用本项目对学校系统正常运行造成负面影响。