package vsphere

import "testing"

func TestVpxPathFromComputeResource(t *testing.T) {
	tests := []struct {
		name          string
		inventoryPath string
		hostName      string
		isCluster     bool
		want          string
		wantErr       bool
	}{
		{
			name:          "standalone host",
			inventoryPath: "/Eco-Datacenter/host/10.46.83.128",
			want:          "/Eco-Datacenter/10.46.83.128",
		},
		{
			name:          "cluster host",
			inventoryPath: "/Eco-Datacenter/host/Eco-Cluster",
			hostName:      "10.46.29.136",
			isCluster:     true,
			want:          "/Eco-Datacenter/Eco-Cluster/10.46.29.136",
		},
		{
			name:          "missing host folder",
			inventoryPath: "/Eco-Datacenter/Eco-Cluster",
			wantErr:       true,
		},
		{
			name:          "cluster requires host name",
			inventoryPath: "/Eco-Datacenter/host/Eco-Cluster",
			isCluster:     true,
			wantErr:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := vpxPathFromComputeResource(test.inventoryPath, test.hostName, test.isCluster)
			if test.wantErr {
				if err == nil {
					t.Fatal("vpxPathFromComputeResource() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("vpxPathFromComputeResource() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("vpxPathFromComputeResource() = %q, want %q", got, test.want)
			}
		})
	}
}
