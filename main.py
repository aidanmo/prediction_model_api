import uvicorn

import pickle

from pydantic import BaseModel

from fastapi import FastAPI

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [

"http://localhost.tiangolo.com",

"https://localhost.tiangolo.com",

"http://localhost",

"http://localhost:8080",

"http://localhost:3000",

]

app.add_middleware(

CORSMiddleware,

allow_origins=origins,

allow_credentials=True,

allow_methods=["*"],

allow_headers=["*"],

)

model = pickle.load(open('../predictive/maliciousUrl.pkl', 'rb'))

class Candidate(BaseModel):

    length_url: int

    length_hostname: int

    ip: int

    nb_dots: int

    nb_hyphens: int

    nb_qm: int

    nb_and: int

    nb_or: int

    nb_eq: int

    nb_underscore: int

    nb_tilde: int

    nb_percent: int

    nb_slash: int

    nb_star: int

    nb_colon: int

    nb_comma: int

    nb_semicolumn: int

    nb_dollar: int

    nb_space: int

    nb_www: int

    nb_com: int

    nb_dslash: int

    http_in_path: int

    https_token: int

    ratio_digits_url: float

    ratio_digits_host: float

    port: int

    tld_in_path: int

    tld_in_subdomain: int

    abnormal_subdomain: int

    nb_subdomains: int

    prefix_suffix: int

    random_domain: int

    shortening_service: int

    path_extension: int

    nb_redirection: int

    nb_external_redirection: int

    length_words_raw: int

    char_repeat: int

    shortest_words_raw: int

    shortest_word_host: int

    shortest_word_path: int

    longest_words_raw: int

    longest_word_host: int

    longest_word_path: int

    avg_words_raw: float

    avg_word_host: float

    avg_word_path: float

    phish_hints: int

    domain_in_brand: int

    brand_in_subdomain: int

    brand_in_path: int

    suspecious_tld: int

    statistical_report: int

    nb_hyperlinks: int

    ratio_intHyperlinks: float

    ratio_extHyperlinks: float

    ratio_nullHyperlinks: float

    nb_extCSS: int

    ratio_intRedirection: float

    ratio_extRedirection: float

    ratio_intErrors: float

    ratio_extErrors: float

    login_form: int

    external_favicon: int

    links_in_tags: float

    submit_email: int 

    ratio_intMedia: float

    ratio_extMedia: float

    sfh: int

    iframe: int

    popup_window: int

    safe_anchor: int

    onmouseover: int

    right_clic: int

    empty_title: int

    domain_in_title: int

    domain_with_copyright: int

    whois_registered_domain: int

    domain_registration_length: int

    domain_age: int

    web_traffic: int

    dns_record: int

    google_index: int

    page_rank: int

@app.get("/")

def read_root():

    return {"data": "Welcome to online malicious URL identifier"}


@app.post("/prediction/")

async def get_predict(data: Candidate):

    sample = [[

    data.length_url,

    data.length_hostname,

    data.ip,

    data.nb_dots,

    data.nb_hyphens,

    data.nb_qm,

    data.nb_and,

    data.nb_or,

    data.nb_eq,

    data.nb_underscore,

    data.nb_tilde,

    data.nb_percent,

    data.nb_slash,

    data.nb_star,

    data.nb_colon,

    data.nb_comma,

    data.nb_semicolumn,

    data.nb_dollar,

    data.nb_space,

    data.nb_www,

    data.nb_com,

    data.nb_dslash,

    data.http_in_path,

    data.https_token,

    data.ratio_digits_url,

    data.ratio_digits_host,

    data.port,

    data.tld_in_path,

    data.tld_in_subdomain,

    data.abnormal_subdomain,

    data.nb_subdomains,

    data.prefix_suffix,

    data.random_domain,

    data.shortening_service,

    data.path_extension,

    data.nb_redirection,

    data.nb_external_redirection,

    data.length_words_raw,

    data.char_repeat,

    data.shortest_words_raw,

    data.shortest_word_host,

    data.shortest_word_path,

    data.longest_words_raw,

    data.longest_word_host,

    data.longest_word_path,

    data.avg_words_raw,

    data.avg_word_host,

    data.avg_word_path,

    data.phish_hints,

    data.domain_in_brand,

    data.brand_in_subdomain,

    data.brand_in_path,

    data.suspecious_tld,

    data.statistical_report,

    data.nb_hyperlinks,

    data.ratio_intHyperlinks,

    data.ratio_extHyperlinks,

    data.ratio_nullHyperlinks,

    data.nb_extCSS,

    data.ratio_intRedirection,

    data.ratio_extRedirection,

    data.ratio_intErrors,

    data.ratio_extErrors,

    data.login_form,

    data.external_favicon,

    data.links_in_tags,

    data.submit_email, 

    data.ratio_intMedia,

    data.ratio_extMedia,

    data.sfh,

    data.iframe,

    data.popup_window,

    data.safe_anchor,

    data.onmouseover,

    data.right_clic,

    data.empty_title,

    data.domain_in_title,

    data.domain_with_copyright,

    data.whois_registered_domain,

    data.domain_registration_length,

    data.domain_age,

    data.web_traffic,

    data.dns_record,

    data.google_index,

    data.page_rank

    ]]

    malicious = model.predict(sample).tolist()[0]

    return {

    "data": {

    'prediction': malicious,

    'interpretation': 'The URL provided is malicious.' if malicious == 1 else 'The URL provided is safe.'

    }

    }

if __name__ == '__main__':

    uvicorn.run(app, port=8080, host='0.0.0.0')






























