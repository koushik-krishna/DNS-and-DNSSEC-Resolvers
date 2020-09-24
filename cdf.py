import numpy as np
import matplotlib.pyplot as plt
plt.style.use('ggplot')

alexa_top_25_websites_dns_query_times_for_our_resolver = np.array([191, 194, 274,
 485, 455, 177, 495, 262, 1062, 209, 663, 539, 160, 664, 270, 1016, 190, 396,
  174, 790, 144, 410, 832, 159, 160])

alexa_top_25_websites_dns_query_times_for_google_public_dns = np.array([15, 16, 94,
 7, 116, 13, 237, 36, 198, 10, 206, 10, 18, 155, 16, 158, 8, 10, 16, 16, 10, 103, 10, 14, 8])

our_resolver_times_sorted = np.sort(alexa_top_25_websites_dns_query_times_for_our_resolver)
google_pub_dns_times_sorted = np.sort(alexa_top_25_websites_dns_query_times_for_google_public_dns)
max_dns_query_time = max(our_resolver_times_sorted[-1], google_pub_dns_times_sorted[-1])
website_count = len(our_resolver_times_sorted)

def generate_CDF_from_data_points(data, data_len, max_dns_query_time):
    cdf_data = []
    if data_len == 0:
        return cdf_data

    cdf_data.append([0, 0])

    cdf_val = 0
    for query_time in data:
        cdf_data.append([query_time, cdf_val])
        cdf_val += (1/website_count)
        cdf_data.append([query_time, cdf_val])

    cdf_data.append([max_dns_query_time + 200, 1])
    return cdf_data

our_resolver_cdf_data = np.array(generate_CDF_from_data_points(
    our_resolver_times_sorted, len(our_resolver_times_sorted), max_dns_query_time))

google_pub_dns_resolver_cdf_data = np.array(generate_CDF_from_data_points(
    google_pub_dns_times_sorted, len(google_pub_dns_times_sorted), max_dns_query_time))

plt.title("CDF for DNS Query Resolution Times")  
plt.xlabel("DNS Query Resolution time in milliseconds")  
plt.ylabel("Fraction of WebSites")  
plt.plot(our_resolver_cdf_data[:, 0], our_resolver_cdf_data[:, 1], color='red')
plt.plot(google_pub_dns_resolver_cdf_data[:, 0], google_pub_dns_resolver_cdf_data[:, 1], color='green')
plt.legend(['Our DNS Resolver', 'Google Public DNS Resolver'])
plt.show()
