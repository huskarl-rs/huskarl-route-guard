use axum::{Router, routing::get};

async fn marker(id: &'static str) -> ([(&'static str, &'static str); 1], &'static str) {
    ([("x-route-id", id)], id)
}

#[tokio::main]
async fn main() {
    // Route IDs only: expected policies live in the independent harness.
    let mut app = Router::new();
    for (prefix, route_id) in [
        ("/admin", "admin"),
        ("/files", "files"),
        ("/files/private", "private"),
    ] {
        for path in [
            prefix.to_owned(),
            format!("{prefix}/"),
            format!("{prefix}/{{*rest}}"),
        ] {
            let route = get(move || marker(route_id));
            let route = if prefix == "/files" {
                route.post(|| marker("files"))
            } else {
                route
            };
            app = app.route(&path, route);
        }
    }
    let app = app.fallback(|| marker("public"));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("fixture listener");
    println!("Axum 0.8.9; Sensitive; no path-rewriting middleware");
    axum::serve(listener, app).await.expect("fixture server");
}
