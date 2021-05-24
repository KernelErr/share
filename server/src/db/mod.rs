use crate::models::file::ShareRecord;
use mongodb::{
    bson::{self, doc},
    Client,
};
use nanoid::nanoid;

pub async fn generate_unique_link(mongodb_client: &Client) -> String {
    let mongodb_db = mongodb_client.database("share");
    let mongodb_records_collection = mongodb_db.collection::<bson::Document>("records");
    let alphabet: [char; 53] = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't',
        'u', 'w', 'x', 'y', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P',
        'Q', 'R', 'S', 'T', 'U', 'W', 'Z', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    let mut flag = false;
    let mut link = nanoid!(8, &alphabet);
    while !flag {
        let result = mongodb_records_collection
            .find_one(
                doc! {
                    "link": &link,
                    "active": true
                },
                None,
            )
            .await
            .unwrap();
        if result.is_some() {
            link = nanoid!(8, &alphabet);
        } else {
            flag = true;
        }
    }
    link
}

pub async fn add_record(mongodb_client: &Client, share_record: &ShareRecord) -> bool {
    let mongodb_db = mongodb_client.database("share");
    let mongodb_records_collection = mongodb_db.collection("records");
    let link = share_record.link.clone();
    let result = mongodb_records_collection
        .find_one(
            doc! {
                "link": link,
                "active": true,
            },
            None,
        )
        .await
        .unwrap();
    if result.is_some() {
        return false;
    }
    let doc = match share_record.password {
        Some(_) => doc! {
            "link": share_record.link.clone(),
            "filename": share_record.filename.clone(),
            "filetype": share_record.filetype.clone(),
            "object_key": share_record.object_key.clone(),
            "content_type": share_record.content_type.clone(),
            "content_length": share_record.content_length as u64,
            "create_time": share_record.create_time,
            "expire_time": share_record.expire_time,
            "password": share_record.password.clone().unwrap(),
            "user": share_record.user.clone(),
            "ip": share_record.ip.clone(),
            "user_agent": share_record.user_agent.clone(),
            "visit_times": share_record.visit_times,
            "active": share_record.active,
            "ban": share_record.ban,
        },
        None => doc! {
            "link": share_record.link.clone(),
            "filename": share_record.filename.clone(),
            "filetype": share_record.filetype.clone(),
            "object_key": share_record.object_key.clone(),
            "content_type": share_record.content_type.clone(),
            "content_length": share_record.content_length as u64,
            "create_time": share_record.create_time,
            "expire_time": share_record.expire_time,
            "password": null,
            "user": share_record.user.clone(),
            "ip": share_record.ip.clone(),
            "user_agent": share_record.user_agent.clone(),
            "visit_times": share_record.visit_times,
            "active": share_record.active,
            "ban": share_record.ban,
        },
    };
    mongodb_records_collection
        .insert_one(doc, None)
        .await
        .is_ok()
}
