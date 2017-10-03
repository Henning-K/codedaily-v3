#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate serde_json;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
extern crate crypto;
extern crate codedaily_backend;
extern crate diesel;

use self::codedaily_backend::*;
use self::codedaily_backend::models::*;
use self::codedaily_backend::middleware::{self, Auth};
use self::codedaily_backend::helpers::*;
use codedaily_backend::schema::links::dsl::*;
use codedaily_backend::schema::users::dsl::*;
use self::diesel::prelude::*;
use rocket_contrib::{Json, Value};
use std::io;
use std::path::{Path, PathBuf};
use rocket::response::NamedFile;

const LINKS_PER_PAGE: i64 = 30;

/// Encrypt passwords using SHA256
fn encrypt_password(input: &str) -> String {
    digest(input)
}

/// Registers a user and creates a record for them in the database.
/// Returns a Json construct containing a "false" result flag if the given user name or email
/// address already exists in the database, otherwise the function returns a "true" result flag
/// and the user data in a Json construct.
#[post("/users/register", format = "application/json", data = "<user>")]
fn register_user(user: Json<User>) -> Json<Value> {
    use schema::users;

    let connection = establish_connection();

    let new_user = NewUser {
        username: user.username.to_string(),
        email: user.email.to_string(),
        password: encrypt_password(&user.password),
        enable: 1,
    };

    let found_exist_user: i32 = users
        .count()
        .filter(users::username.eq(&new_user.username).or(users::email.eq(
            &new_user.email,
        )))
        .get_result(&connection)
        .unwrap_or(0) as i32;

    if found_exist_user <= 0 {
        let result: User = diesel::insert(&new_user)
            .into(users::table)
            .get_result(&connection)
            .expect("Error creating user");
        Json(json!({
            "result": result
        }))
    } else {
        Json(json!({
            "result": false
        }))
    }
}

/// Logs a user in by creating an auth token, an expiry date and inserting a record of these into
/// the DB. Returns a "false" result flag wrapped in Json if the user could not be found
/// (or the password does not match), otherwise returns a Json construct containing a "true"
/// result flag, the user name, the user's email address and the auth token which then also
///  exists in the DB.
#[post("/users/login", format = "application/json", data = "<user>")]
fn login_user(user: Json<Value>) -> Json<Value> {
    use schema::auth_tokens;

    let connection = establish_connection();

    let t_username = user["username"].as_str().unwrap_or("");
    let t_password = encrypt_password(user["password"].as_str().unwrap_or(""));

    let result = User::find_by_login(&connection, t_username, t_password.as_str());

    match result {
        Ok(user) => {
            let rand_hash = gen_random_hash();
            let expired_at = (epoch_now() as i64) + AUTH_TOKEN_TTL;
            let new_auth_token = AuthToken {
                token: rand_hash,
                expired_at: expired_at,
                user_id: user.id,
            };
            let result: AuthToken = diesel::insert(&new_auth_token)
                .into(auth_tokens::table)
                .get_result(&connection)
                .expect("Error creating auth token");

            Json(json!({
                "result": true,
                "user": {
                    "username": user.username,
                    "email": user.email,
                },
                "token": result.token,
            }))
        }
        Err(_) => {
            Json(json!({
                "result": false,
            }))
        }
    }
}

/// Attempts to find the logged-in user by their user ID.
/// Panics if the user is not found otherwise returns a "true" result flag, the user name,
/// the user's email address and the auth token wrapped in a Json construct.
#[get("/users/me")]
fn get_user(auth: Auth) -> Json<Value> {
    let connection = establish_connection();

    let user = User::find(&connection, auth.user_id).unwrap();

    Json(json!({
        "result": true,
        "user": {
            "username": user.username,
            "email": user.email,
        },
        "token": auth.token,
    }))
}

/// Attempts to read LINKS_PER_PAGE number of links from the DB, sorted by time in descending
/// order, returning a "success" status flag, the links and the number of links found (if any)
/// in a Json construct.
#[get("/feed/<page>")]
fn feed(page: i64) -> Json<Value> {
    let connection = establish_connection();
    let mut offset = (page - 1) * LINKS_PER_PAGE;
    if offset < 0 {
        offset = 0;
    }
    let results = links
        .order(time.desc())
        .offset(offset)
        .limit(LINKS_PER_PAGE)
        .load::<Link>(&connection)
        .ok();
    let total = links.order(time.desc()).load::<Link>(&connection).ok();
    let mut count = 0;
    if total.is_some() {
        count = total.unwrap().len();
    }
    Json(json!({
        "status": "success",
        "links": results,
        "total": count
    }))
}

/// Opens the "www/index.html" file in response to the default route "/" being
/// requested by the client.
#[get("/")]
fn index() -> io::Result<NamedFile> {
    NamedFile::open("www/index.html")
}

/// Returns the file in the www/ folder given by name in the client's request,
/// wrapped in an Option.
#[get("/<file..>", rank = 5)]
fn files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("www/").join(file)).ok()
}

/// Main function of the server.
/// Creates a new Rocket instance, "mounts" the routes given above and launches the server.
fn main() {
    rocket::ignite()
        .mount("/api/", routes![feed, register_user, login_user, get_user])
        .mount("/", routes![index, files])
        .launch();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // test with:
    // `cargo test -- --test-threads=1`

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Login {
        username: String,
        password: String,
    }

    fn common() -> Vec<User> {
        let db_reset = Command::new("diesel")
            .arg("database")
            .arg("reset")
            .output()
            .expect("DB reset before test_register_user failed.");
        assert!(db_reset.status.success());

        let user1 = User {
            id: 1,
            username: "user1".to_owned(),
            password: "pass1".to_owned(),
            email: "user1@example.org".to_owned(),
            enable: 1,
        };

        let user2 = User {
            id: 1,
            username: "user2".to_owned(),
            password: "asdf!§$%".to_owned(),
            email: "user2@example.org".to_owned(),
            enable: 1,
        };

        let mut registered_users = vec![];

        registered_users.push(User {
            password: user1.clone().password,
            ..serde_json::from_value(
                register_user(Json(user1.clone())).into_inner()["result"].clone(),
            ).unwrap()
        });
        registered_users.push(User {
            password: user2.clone().password,
            ..serde_json::from_value(
                register_user(Json(user2.clone())).into_inner()["result"].clone(),
            ).unwrap()
        });

        registered_users
    }

    #[test]
    fn test_encrypt() {
        assert_eq!(encrypt_password("test"), String::from("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
        assert_eq!(encrypt_password("admin"), String::from("8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"));
        assert_eq!(encrypt_password("password123"), String::from("ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"));
        assert_eq!(encrypt_password("asdf!§$%"), String::from("dce524145c8b31fdab6c924e6245efec9b3a348e03646577cf0da89848fadafb"));
    }

    #[test]
    fn test_register_user() {
        let db_reset = Command::new("diesel")
            .arg("database")
            .arg("reset")
            .output()
            .expect("DB reset before test_register_user failed.");
        assert!(db_reset.status.success());

        let user1 = User {
            id: 1,
            username: "user1".to_owned(),
            password: "pass1".to_owned(),
            email: "user1@example.org".to_owned(),
            enable: 1,
        };

        let user2 = User {
            id: 1,
            username: "user2".to_owned(),
            password: "asdf!§$%".to_owned(),
            email: "user2@example.org".to_owned(),
            enable: 1,
        };

        // same as user1, just different username, this should return false since the email is
        // already in the DB.
        let user1_2 = User {
            username: "user3".to_string(),
            ..user1.clone()
        };

        // same as user2, just different email, this should return false
        let user2_2 = User {
            email: "user2_2@example.org".to_string(),
            ..user2.clone()
        };

        let false_result = json!({ "result": false });

        assert_ne!(register_user(Json(user1.clone())).into_inner(), false_result);
        assert_ne!(register_user(Json(user2.clone())).into_inner(), false_result);
        assert_eq!(register_user(Json(user1_2.clone())).into_inner(), false_result);
        assert_eq!(register_user(Json(user2_2.clone())).into_inner(), false_result);
        assert_eq!(register_user(Json(user1.clone())).into_inner(), false_result);
        assert_eq!(register_user(Json(user2.clone())).into_inner(), false_result);
    }

    #[test]
    fn test_login_user() {
        let mut reg_users = common(); // set up test data

        let user2: User = reg_users.pop().unwrap();
        let user1: User = reg_users.pop().unwrap();

        let login1 = Login {
            username: user1.username,
            password: user1.password,
        };

        let login2 = Login {
            username: user2.username,
            password: user2.password,
        };

        let login1_2 = Login {
            username: "user3".to_string(),
            ..login1.clone()
        };
        let login2_2 = Login {
            password: "multipass".to_string(),
            ..login2.clone()
        };

        let false_result = json!({ "result": false });

        // login works
        assert_ne!(login_user(Json(json!(login1.clone()))).into_inner(), false_result);
        assert_ne!(login_user(Json(json!(login2.clone()))).into_inner(), false_result);

        // login does not work, since username or password don't match.
        assert_eq!(login_user(Json(json!(login1_2.clone()))).into_inner(), false_result);
        assert_eq!(login_user(Json(json!(login2_2.clone()))).into_inner(), false_result);
    }

    #[test]
    fn test_get_user() {
        let mut reg_users = common(); // set up test data

        let user2: User = reg_users.pop().unwrap();
        let user1: User = reg_users.pop().unwrap();

        let login1 = Login {
            username: user1.username,
            password: user1.password,
        };

        let login2 = Login {
            username: user2.username,
            password: user2.password,
        };

        let logged_in1 = login_user(Json(json!(login1.clone()))).into_inner();
        let logged_in2 = login_user(Json(json!(login2.clone()))).into_inner();

        let token1 = logged_in1["token"].as_str().unwrap_or("token1");
        let token2 = logged_in2["token"].as_str().unwrap_or("token2");

        let conn = establish_connection();
        let auth1 = middleware::authenticate(&conn, &token1).unwrap();
        let auth2 = middleware::authenticate(&conn, &token2).unwrap();

        // login_user returns basically the same data as get_user.
        assert_eq!(get_user(auth1).into_inner(), logged_in1);
        assert_eq!(get_user(auth2).into_inner(), logged_in2);
    }

    #[test]
    fn test_index() {
        use std::fs::File;
        use std::io::Read;

        let get_index = index().unwrap();
        let mut index_file = get_index.take_file();
        let mut file_to_be = File::open("www/index.html").unwrap();

        let (mut buf1, mut buf2) = (String::new(), String::new());
        index_file.read_to_string(&mut buf1).unwrap();
        file_to_be.read_to_string(&mut buf2).unwrap();

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_file() {
        use std::fs::File;
        use std::io::Read;

        let get_file = files("main.js".into()).unwrap();
        let mut index_file = get_file.take_file();
        let mut file_to_be = File::open("www/main.js").unwrap();

        let (mut buf1, mut buf2) = (String::new(), String::new());
        index_file.read_to_string(&mut buf1).unwrap();
        file_to_be.read_to_string(&mut buf2).unwrap();

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_feed() {
        // TODO
    }
}
